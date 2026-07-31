// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"errors"
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

// Install is one GitHub App installation for an owner.
type Install struct {
	Transport *ghinstallation.AppsTransport
	ID        int64 // installation ID
	AppID     int64 // owning App ID, for logging and dedup
}

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

	// GetAll returns every installation for owner across all configured Apps,
	// in a stable order. It returns an empty slice and a nil error when the
	// owner has no installations.
	//
	// Unlike Get, GetAll performs no routing or capacity selection. Callers
	// that must reason about ALL installations — rather than pick one — use
	// this. Get is a routing primitive and repeated calls may return the same
	// installation, so it cannot be used to enumerate.
	//
	// A non-nil error means the enumeration is NOT exhaustive, even if the
	// returned slice is non-empty. Callers that require exhaustiveness for
	// correctness must treat that as unknown rather than as a complete answer.
	GetAll(ctx context.Context, owner string) ([]Install, error)
}

const defaultNegativeTTL = 5 * time.Minute

type manager struct {
	atr           *ghinstallation.AppsTransport
	baseURL       string
	cache         *lru.TwoQueueCache[string, int64]
	negativeCache *expirablelru.LRU[string, bool]
}

// New creates a Manager backed by the given AppsTransport.
func New(atr *ghinstallation.AppsTransport) (Manager, error) {
	return NewWithOptions(atr, defaultNegativeTTL, "")
}

// NewWithBaseURL creates a Manager with a custom GitHub API base URL
// (for GitHub Enterprise Server). When baseURL is empty, the default
// https://api.github.com is used.
func NewWithBaseURL(atr *ghinstallation.AppsTransport, baseURL string) (Manager, error) {
	return NewWithOptions(atr, defaultNegativeTTL, baseURL)
}

// NewWithNegativeTTL creates a Manager with a configurable TTL for
// negative (not-installed) cache entries.
func NewWithNegativeTTL(atr *ghinstallation.AppsTransport, negativeTTL time.Duration) (Manager, error) {
	return NewWithOptions(atr, negativeTTL, "")
}

// NewWithOptions creates a Manager with configurable negative-cache TTL and
// GitHub API base URL (for GitHub Enterprise Server). When baseURL is empty,
// the default https://api.github.com is used.
func NewWithOptions(atr *ghinstallation.AppsTransport, negativeTTL time.Duration, baseURL string) (Manager, error) {
	cache, err := lru.New2Q[string, int64](200)
	if err != nil {
		return nil, err
	}
	return &manager{
		atr:           atr,
		baseURL:       baseURL,
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

	opts := []github.ClientOptionsFunc{github.WithTransport(m.atr)}
	if m.baseURL != "" {
		opts = append(opts, github.WithEnterpriseURLs(m.baseURL, m.baseURL))
	}
	client, err := github.NewClient(opts...)
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

// GetAll returns this app's single installation for owner, if any. Delegates to
// Get, so it shares the LRU and negative caches. A not-installed owner yields
// an empty slice rather than an error, because "no installations" is a complete
// answer whereas an error means the enumeration failed.
func (m *manager) GetAll(ctx context.Context, owner string) ([]Install, error) {
	atr, id, err := m.Get(ctx, owner, "", "")
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return []Install{{Transport: atr, ID: id, AppID: m.atr.AppID()}}, nil
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

// GetAll concatenates every manager's installations for owner, in managers
// order, deduplicated on installation ID.
//
// If any manager fails to enumerate, the successful results are returned
// alongside an error: the list is real but incomplete, and a caller that needs
// exhaustiveness must not treat it as the whole set.
func (rr *roundRobin) GetAll(ctx context.Context, owner string) ([]Install, error) {
	var out []Install
	var errs []error
	seen := make(map[int64]bool, len(rr.managers))

	for _, m := range rr.managers {
		installs, err := m.GetAll(ctx, owner)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, in := range installs {
			if seen[in.ID] {
				continue
			}
			seen[in.ID] = true
			out = append(out, in)
		}
	}

	if len(errs) > 0 {
		return out, fmt.Errorf("enumerating installations for %q: %w", owner, errors.Join(errs...))
	}
	return out, nil
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
