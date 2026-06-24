// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
	lru "github.com/hashicorp/golang-lru/v2"
	expirablelru "github.com/hashicorp/golang-lru/v2/expirable"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Manager looks up GitHub App installations by owner.
// scope and identity are used by multi-app implementations for routing;
// single-app implementations may ignore them.
type Manager interface {
	// Get returns the transport and installation ID for the given owner.
	// For multi-app managers (e.g. roundRobin), scope and identity inform
	// routing decisions such as capacity-aware selection. Single-app
	// managers ignore them.
	Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error)

	// GetByInstallation returns the transport for a specific installation ID
	// if it belongs to the given owner. Used by the sticky store to retrieve
	// a previously-persisted installation.
	GetByInstallation(ctx context.Context, owner string, installationID int64) (*ghinstallation.AppsTransport, int64, error)
}

const defaultNegativeTTL = 5 * time.Minute

type manager struct {
	atr           *ghinstallation.AppsTransport
	cache         *lru.TwoQueueCache[string, int64]
	negativeCache *expirablelru.LRU[string, bool]
}

// New creates a Manager backed by the given AppsTransport.
func New(atr *ghinstallation.AppsTransport) (Manager, error) {
	return NewWithNegativeTTL(atr, defaultNegativeTTL)
}

// NewWithNegativeTTL creates a Manager with a configurable TTL for
// negative (not-installed) cache entries.
func NewWithNegativeTTL(atr *ghinstallation.AppsTransport, negativeTTL time.Duration) (Manager, error) {
	cache, err := lru.New2Q[string, int64](200)
	if err != nil {
		return nil, err
	}
	return &manager{
		atr:           atr,
		cache:         cache,
		negativeCache: expirablelru.NewLRU[string, bool](200, nil, negativeTTL),
	}, nil
}

// Get returns the AppsTransport and installation ID for the given owner.
// scope and identity are unused by the single-app manager; routing across
// apps is handled by the roundRobin manager.
func (m *manager) Get(ctx context.Context, owner, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	cacheKey := fmt.Sprintf("%d/%s", m.atr.AppID(), owner)
	if _, ok := m.negativeCache.Get(cacheKey); ok {
		clog.InfoContextf(ctx, "negative install cache hit for %s", cacheKey)
		return nil, 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
	}
	if v, ok := m.cache.Get(cacheKey); ok {
		clog.InfoContextf(ctx, "found installation in cache for %s", cacheKey)
		return m.atr, v, nil
	}

	client, err := github.NewClient(github.WithTransport(m.atr))
	if err != nil {
		return nil, 0, status.Errorf(codes.Internal, "creating GitHub client: %v", err)
	}
	// Walk through the pages of installations looking for an organization
	// matching owner.
	page := 1
	for page != 0 {
		installs, resp, err := client.Apps.ListInstallations(ctx, &github.ListOptions{
			Page:    page,
			PerPage: 100,
		})
		if err != nil {
			return nil, 0, status.Errorf(codes.Internal, "listing installations: %v", err)
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
	m.negativeCache.Add(cacheKey, true)
	return nil, 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
}

// GetByInstallation returns this app's transport if its installation for
// the given owner matches installationID. Delegates to Get, which serves
// from the LRU cache on the hot path and calls ListInstallations on a
// cold cache (once per app per owner after a deploy).
func (m *manager) GetByInstallation(ctx context.Context, owner string, installationID int64) (*ghinstallation.AppsTransport, int64, error) {
	atr, id, err := m.Get(ctx, owner, "", "")
	if err != nil {
		return nil, 0, err
	}
	if id != installationID {
		return nil, 0, status.Errorf(codes.NotFound, "installation %d not found for %q", installationID, owner)
	}
	return atr, id, nil
}

// QuotaConfig configures three-tier capacity-aware selection for the
// roundRobin manager.
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
// the cold-start strategy, optionally with capacity-aware selection layered
// on top via QuotaConfig. It does not use scope or identity for routing, so
// different callers with the same (scope, identity) may land on different
// apps. Use this only when the caller's trust policy does not require
// checks:write — i.e., when there is no GitHub check-run ownership
// constraint.
type roundRobin struct {
	managers []Manager
	counter  atomic.Uint64
	quota    *QuotaConfig
}

// NewRoundRobin creates a Manager that distributes requests across the given
// managers using an atomic round-robin counter.
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

// Get selects an installation for the given owner. When quota data is
// available the capacity-aware picker chooses the install with the most
// headroom; otherwise the atomic counter distributes evenly.
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

// GetByInstallation iterates the underlying managers to find the one
// whose installation for the given owner matches installationID. Each
// manager serves from its LRU cache on the hot path, so this is a
// series of in-memory lookups after warmup.
func (rr *roundRobin) GetByInstallation(ctx context.Context, owner string, installationID int64) (*ghinstallation.AppsTransport, int64, error) {
	for _, m := range rr.managers {
		atr, id, err := m.GetByInstallation(ctx, owner, installationID)
		if err == nil {
			return atr, id, nil
		}
	}
	return nil, 0, status.Errorf(codes.NotFound, "installation %d not found for %q", installationID, owner)
}

// pickByQuota selects an installed manager using three-tier capacity-aware
// fairshare. Returns ok=false when quota selection cannot proceed (no config,
// or any candidate lacks quota data) — callers fall back to the atomic
// counter. This ensures the counter distributes evenly on cold start until
// every installation has been seen at least once via the transport tap.
//
//	comfortable = installs with remaining >= SoftFloor
//	tight       = installs with HardFloor <= remaining < SoftFloor
//	last_resort = installs with remaining < HardFloor
//
// The first non-empty pool wins; within a pool the install with the most
// absolute remaining headroom is selected.
func pickByQuota(ctx context.Context, managers []Manager, owner, scope, identity string, q *QuotaConfig) (*ghinstallation.AppsTransport, int64, bool) {
	if q == nil || q.Store == nil {
		return nil, 0, false
	}
	if ctx.Err() != nil {
		return nil, 0, false
	}

	type cand struct {
		atr       *ghinstallation.AppsTransport
		installID int64
		remaining int
	}

	var candidates []cand
	for _, m := range managers {
		atr, id, err := m.Get(ctx, owner, scope, identity)
		if err != nil {
			continue
		}
		rem, _, ok := q.Store.Get(id)
		if !ok {
			return nil, 0, false
		}
		candidates = append(candidates, cand{atr, id, rem})
	}

	if len(candidates) == 0 {
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
