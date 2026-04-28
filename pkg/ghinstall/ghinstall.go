// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"sync/atomic"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v84/github"
	lru "github.com/hashicorp/golang-lru/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Manager looks up GitHub App installations by owner.
// scope and identity are used by multi-app implementations for routing;
// single-app implementations may ignore them.
type Manager interface {
	Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error)
}

type manager struct {
	atr   *ghinstallation.AppsTransport
	cache *lru.TwoQueueCache[string, int64]
}

// New creates a Manager backed by the given AppsTransport.
func New(atr *ghinstallation.AppsTransport) (Manager, error) {
	cache, err := lru.New2Q[string, int64](200)
	if err != nil {
		return nil, err
	}
	return &manager{
		atr:   atr,
		cache: cache,
	}, nil
}

// Get returns the AppsTransport and installation ID for the given owner.
// scope and identity are unused by the single-app manager; routing is handled
// by multiManager.
func (m *manager) Get(ctx context.Context, owner, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	cacheKey := fmt.Sprintf("%d/%s", m.atr.AppID(), owner)
	if v, ok := m.cache.Get(cacheKey); ok {
		clog.InfoContextf(ctx, "found installation in cache for %s", cacheKey)
		return m.atr, v, nil
	}

	client := github.NewClient(&http.Client{
		Transport: m.atr,
	})
	// Walk through the pages of installations looking for an organization
	// matching owner.
	page := 1
	for page != 0 {
		installs, resp, err := client.Apps.ListInstallations(ctx, &github.ListOptions{
			Page:    page,
			PerPage: 100,
		})
		if err != nil {
			return nil, 0, err
		}

		for _, install := range installs {
			if install.Account.GetLogin() == owner {
				installID := install.GetID()
				m.cache.Add(cacheKey, installID)
				return m.atr, installID, nil
			}
		}
		page = resp.NextPage
	}
	return nil, 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
}

// QuotaConfig configures three-tier capacity-aware selection. When set on a
// Manager, the Get path first attempts to pick the install with the most
// absolute remaining quota among those above the soft floor, falling back
// through tighter pools before reaching the cold-start strategy.
type QuotaConfig struct {
	// Store is the source of per-installation remaining-quota snapshots,
	// populated by the ghtransport response tap. May be nil to disable
	// quota-aware selection.
	Store *QuotaStore
	// SoftFloor: remaining < SoftFloor demotes an install out of the
	// preferred pool. Heavy/sticky callers landing on the preferred pool
	// always have at least SoftFloor headroom.
	SoftFloor int
	// HardFloor: remaining < HardFloor excludes an install entirely except
	// when every install is below it ("last resort").
	HardFloor int
}

// roundRobin distributes requests across managers using an atomic counter as
// the cold-start strategy. When a non-nil QuotaConfig is provided, requests
// first try capacity-aware selection.
type roundRobin struct {
	managers []Manager
	counter  atomic.Uint64
	quota    *QuotaConfig
}

// NewRoundRobin creates a Manager that distributes requests across the given
// managers using an atomic round-robin counter on cold start.
func NewRoundRobin(managers []Manager) Manager {
	if len(managers) == 0 {
		panic("ghinstall: NewRoundRobin requires at least one manager")
	}
	return &roundRobin{managers: managers}
}

// NewRoundRobinWithQuota is NewRoundRobin with capacity-aware selection
// layered on top. When quota data is available, requests are routed via
// argmax(remaining) within the highest non-empty tier (comfortable, tight,
// or last-resort). When no candidate has quota data, the atomic counter is
// used.
func NewRoundRobinWithQuota(managers []Manager, q *QuotaConfig) Manager {
	if len(managers) == 0 {
		panic("ghinstall: NewRoundRobinWithQuota requires at least one manager")
	}
	return &roundRobin{managers: managers, quota: q}
}

func (rr *roundRobin) Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error) {
	if atr, id, ok := pickByQuota(ctx, rr.managers, owner, scope, identity, rr.quota); ok {
		return atr, id, nil
	}

	idx := rr.counter.Add(1) % uint64(len(rr.managers))

	atr, id, err := rr.managers[idx].Get(ctx, owner, scope, identity)
	if err == nil {
		return atr, id, nil
	}

	// If the selected app is not installed for this owner, try the remaining
	// apps in order so that installation gaps are handled gracefully.
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		clog.InfoContextf(ctx, "app not installed for %q, trying other apps", owner)
		for i, m := range rr.managers {
			if uint64(i) == idx {
				continue
			}
			atr, id, err = m.Get(ctx, owner, scope, identity)
			if err == nil {
				return atr, id, nil
			}
		}
	}

	return nil, 0, err
}

type multiManager struct {
	managers []Manager
	quota    *QuotaConfig
}

// NewMultiManager creates a Manager that distributes requests across the given
// managers using consistent hashing on the (scope, identity) tuple.
//
// Consistent hashing ensures that the same owner always maps to the same
// GitHub App. This is required because GitHub check runs can only be updated
// by the app that created them — non-deterministic app selection causes 403
// errors when a token refresh or process restart lands on a different app.
//
// Load is distributed across apps by owner: different owners hash to different
// apps. If the selected app is not installed for an owner, the remaining apps
// are tried in order.
func NewMultiManager(managers []Manager) Manager {
	if len(managers) == 0 {
		panic("ghinstall: NewMultiManager requires at least one manager")
	}
	return &multiManager{managers: managers}
}

// NewMultiManagerWithQuota is NewMultiManager with capacity-aware selection
// layered on top. When quota data is available, requests are routed via
// argmax(remaining) within the highest non-empty tier (comfortable, tight,
// or last-resort). When no candidate has quota data, consistent hashing is
// used.
//
// Note that this trades the strict (scope, identity) determinism of
// consistent hashing for capacity-aware distribution. Callers that hold a
// minted token across many GitHub calls (e.g. via oauth2.ReuseTokenSource)
// retain stickiness within the lifetime of a single token, but successive
// Exchange calls for the same (scope, identity) may route to different
// Apps and cannot update GitHub check runs created by a previous App.
// Operators who require strict check-run ownership preservation should
// continue to use NewMultiManager.
func NewMultiManagerWithQuota(managers []Manager, q *QuotaConfig) Manager {
	if len(managers) == 0 {
		panic("ghinstall: NewMultiManagerWithQuota requires at least one manager")
	}
	return &multiManager{managers: managers, quota: q}
}

func (rr *multiManager) Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error) {
	if atr, id, ok := pickByQuota(ctx, rr.managers, owner, scope, identity, rr.quota); ok {
		return atr, id, nil
	}

	// Consistent hashing on (scope, identity): the same requester acting on
	// the same repo always maps to the same GitHub App. This is required
	// because GitHub check runs can only be updated by the app that created
	// them — non-deterministic app selection causes 403 errors.
	//
	// Hashing on both scope and identity (rather than owner alone) distributes
	// load across apps: different identities acting on the same repo, or the
	// same identity acting on different repos, can land on different apps.
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope + ":" + identity))
	primary := int(h.Sum32()) % len(rr.managers)

	atr, id, err := rr.managers[primary].Get(ctx, owner, scope, identity)
	if err == nil {
		return atr, id, nil
	}

	// If the selected app is not installed for this owner, try the remaining
	// apps in order so that installation gaps are handled gracefully.
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		clog.InfoContextf(ctx, "app not installed for %q, trying other apps", owner)
		for i, m := range rr.managers {
			if i == primary {
				continue
			}
			atr, id, err = m.Get(ctx, owner, scope, identity)
			if err == nil {
				return atr, id, nil
			}
		}
	}

	return nil, 0, err
}

// pickByQuota selects an installed manager using three-tier capacity-aware
// fairshare. Returns ok=false when quota selection cannot proceed (no config,
// or no candidate has known quota data) — callers fall back to their cold-
// start strategy.
//
//	comfortable = installs with remaining >= SoftFloor
//	tight       = installs with HardFloor <= remaining < SoftFloor
//	last_resort = installs with remaining < HardFloor
//
// The first non-empty pool wins; within a pool, argmax(remaining) — the
// install with the most absolute headroom — is selected. Heavy callers thus
// land on the install best able to absorb them.
//
// A candidate without quota data is included as if it had remaining = limit
// = SoftFloor + 1 so that newly-seen installs are explored. Until at least
// one candidate has known data, ok=false to keep cold-start deterministic
// (FNV hash for multiManager, atomic counter for roundRobin).
func pickByQuota(ctx context.Context, managers []Manager, owner, scope, identity string, q *QuotaConfig) (*ghinstallation.AppsTransport, int64, bool) {
	if q == nil || q.Store == nil {
		return nil, 0, false
	}

	type cand struct {
		atr       *ghinstallation.AppsTransport
		installID int64
		remaining int
	}

	var candidates []cand
	anyKnown := false
	for _, m := range managers {
		atr, id, err := m.Get(ctx, owner, scope, identity)
		if err != nil {
			continue
		}
		rem, _, ok := q.Store.Get(id)
		if ok {
			anyKnown = true
		} else {
			// Treat unknowns as "just above the soft floor" — they're
			// candidates worth exploring, but known-comfortable installs
			// (which have remaining >> SoftFloor early in the hour) win.
			rem = q.SoftFloor + 1
		}
		candidates = append(candidates, cand{atr, id, rem})
	}

	if !anyKnown || len(candidates) == 0 {
		return nil, 0, false
	}

	pickFromPool := func(pool []cand) cand {
		best := pool[0]
		for _, c := range pool[1:] {
			if c.remaining > best.remaining {
				best = c
			}
		}
		return best
	}

	var comfortable, tight, lastResort []cand
	for _, c := range candidates {
		switch {
		case c.remaining >= q.SoftFloor:
			comfortable = append(comfortable, c)
		case c.remaining >= q.HardFloor:
			tight = append(tight, c)
		default:
			lastResort = append(lastResort, c)
		}
	}

	pool := comfortable
	tier := "comfortable"
	if len(pool) == 0 {
		pool = tight
		tier = "tight"
	}
	if len(pool) == 0 {
		pool = lastResort
		tier = "last_resort"
	}
	if len(pool) == 0 {
		return nil, 0, false
	}

	chosen := pickFromPool(pool)
	clog.DebugContextf(ctx, "ghinstall: quota-aware pick install=%d tier=%s remaining=%d", chosen.installID, tier, chosen.remaining)
	return chosen.atr, chosen.installID, true
}
