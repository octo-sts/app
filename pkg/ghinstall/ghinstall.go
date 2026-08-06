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

// Installation is one GitHub App installation for an owner.
type Installation struct {
	Transport *ghinstallation.AppsTransport
	ID        int64 // installation ID
	AppID     int64 // owning App ID, for logging
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
	// in managers order — the order in which the underlying Manager instances
	// were configured (e.g. the slice passed to NewRoundRobin). It returns no
	// installations and a nil error when the owner has no installations.
	//
	// Unlike Get, GetAll performs no routing or capacity selection. Callers
	// that must reason about ALL installations — rather than pick one — use
	// this. Get is a routing primitive and repeated calls may return the same
	// installation, so it cannot be used to enumerate.
	//
	// Ordering is not stable across calls when a manager that failed on one
	// call succeeds on the next (or vice versa): whichever managers respond
	// successfully occupy the early indices. Callers must not read index 0 as
	// "the preferred App".
	//
	// A non-nil error means the enumeration is NOT exhaustive, even if the
	// returned slice is non-empty. Callers that require exhaustiveness for
	// correctness must treat that as unknown rather than as a complete answer.
	//
	// Exhaustiveness is further bounded by Get's cache: the positive LRU has
	// no TTL (unlike the negative cache), so the returned set is every
	// installation this process has observed, not every installation that
	// currently exists. An App uninstalled from an org keeps appearing here
	// indefinitely; a newly-installed App stays invisible until any negative
	// cache entry for it expires. That missing App is reported as a nil error, so
	// an incomplete enumeration is indistinguishable from a complete one; a caller
	// whose conclusion becomes UNSAFE when an App is missing must confirm with
	// GetAllFresh.
	//
	// Callers must test len(), not nil-ness: implementations differ in whether
	// an empty result is a nil or a zero-length slice.
	GetAll(ctx context.Context, owner string) ([]Installation, error)

	// GetAllFresh enumerates like GetAll but does NOT consult the negative
	// (not-installed) cache, so an App installed within the last negativeTTL is
	// visible. The positive cache IS still consulted, so after an
	// uninstall/reinstall this can report a stale ID; that fails closed, since
	// the stale ID's token mint fails rather than agreeing. It bypasses this
	// process's negative cache, not GitHub's replication, so it narrows the
	// window rather than eliminating it.
	//
	// Use it to CONFIRM an absence conclusion GetAll can only support over
	// observed state. It costs one ListInstallations walk per App with no
	// positive cache entry, so it does not belong on a hot path. Like GetAll, a
	// non-nil error means the enumeration is NOT exhaustive even if the returned
	// slice is non-empty, and callers must test len() rather than nil-ness.
	GetAllFresh(ctx context.Context, owner string) ([]Installation, error)
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

// lookupInstallation walks this App's installations looking for owner.
//
// It consults and populates no caches, which lets Get and GetAllFresh share the
// walk while disagreeing about the negative cache. A false found with a nil error
// is a complete answer (not installed); a failed walk is not.
func (m *manager) lookupInstallation(ctx context.Context, owner string) (int64, bool, error) {
	opts := []github.ClientOptionsFunc{github.WithTransport(m.atr)}
	if m.baseURL != "" {
		opts = append(opts, github.WithEnterpriseURLs(m.baseURL, m.baseURL))
	}
	client, err := github.NewClient(opts...)
	if err != nil {
		return 0, false, status.Errorf(codes.Internal, "creating GitHub client: %v", err)
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
			return 0, false, status.Errorf(codes.Internal, "listing installations for app %d: %v", m.atr.AppID(), err)
		}

		for _, install := range installs {
			if install.Account.GetLogin() == owner {
				return install.GetID(), true, nil
			}
		}
		page = resp.NextPage
	}
	return 0, false, nil
}

// cacheKey is the shared key for both of manager's caches. Get and GetAllFresh
// MUST agree on it: GetAllFresh clears the negative entry Get reads, so a
// divergence here silently restores the shadowing described on setInstalled.
func (m *manager) cacheKey(owner string) string {
	return fmt.Sprintf("%d/%s", m.atr.AppID(), owner)
}

// setInstalled records that owner IS installed, clearing any negative entry that
// would shadow it: Get reads the negative cache before the positive one, so a
// negative entry left alongside a positive one means NotFound for the rest of the
// negative TTL. Remove precedes Add because manager has no mutex — a concurrent
// reader landing between the two sees neither entry and does a fresh walk,
// whereas the other order leaves it reading the stale negative entry.
//
// This narrows that window rather than closing it, and establishes no global
// invariant: a Get whose walk finished before the install can still call
// setNotInstalled afterwards and re-shadow this entry. The residual fails safe as
// a spurious NotFound, so routing rejects rather than grants.
func (m *manager) setInstalled(cacheKey string, id int64) {
	m.negativeCache.Remove(cacheKey)
	m.cache.Add(cacheKey, id)
}

// setNotInstalled records that owner is NOT installed. Only ever called after a
// completed walk found nothing — a failed walk is ignorance, not absence.
func (m *manager) setNotInstalled(cacheKey string) {
	m.negativeCache.Add(cacheKey, true)
}

// Get returns the AppsTransport and installation ID for the given owner.
// scope and identity are unused by the single-app manager; routing across
// apps is handled by the roundRobin manager.
func (m *manager) Get(ctx context.Context, owner, _, _ string) (*ghinstallation.AppsTransport, int64, error) {
	cacheKey := m.cacheKey(owner)
	if _, ok := m.negativeCache.Get(cacheKey); ok {
		clog.InfoContextf(ctx, "negative install cache hit for %s", cacheKey)
		return nil, 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
	}
	if v, ok := m.cache.Get(cacheKey); ok {
		clog.InfoContextf(ctx, "found installation in cache for %s", cacheKey)
		return m.atr, v, nil
	}

	id, found, err := m.lookupInstallation(ctx, owner)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		m.setNotInstalled(cacheKey)
		return nil, 0, status.Errorf(codes.NotFound, "no installation found for %q", owner)
	}
	m.setInstalled(cacheKey, id)
	return m.atr, id, nil
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

// GetAll returns this app's single installation for owner, if any. Delegates
// to Get, so it shares the LRU and negative caches. A not-installed owner
// yields no installations rather than an error, because "no installations" is
// a complete answer whereas a non-nil error means the enumeration failed.
func (m *manager) GetAll(ctx context.Context, owner string) ([]Installation, error) {
	atr, id, err := m.Get(ctx, owner, "", "")
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}
	return []Installation{{Transport: atr, ID: id, AppID: m.atr.AppID()}}, nil
}

// GetAllFresh implements Manager. See the interface for the contract.
func (m *manager) GetAllFresh(ctx context.Context, owner string) ([]Installation, error) {
	cacheKey := m.cacheKey(owner)
	if v, ok := m.cache.Get(cacheKey); ok {
		// Re-assert rather than read through: otherwise a negative entry armed
		// after an earlier confirm cleared it is never repaired.
		m.setInstalled(cacheKey, v)
		return []Installation{{Transport: m.atr, ID: v, AppID: m.atr.AppID()}}, nil
	}

	id, found, err := m.lookupInstallation(ctx, owner)
	if err != nil {
		return nil, err
	}
	if !found {
		// A confirmed absence is as cacheable here as in Get; without this every
		// confirm pays a full walk.
		m.setNotInstalled(cacheKey)
		return nil, nil
	}

	m.setInstalled(cacheKey, id)
	return []Installation{{Transport: m.atr, ID: id, AppID: m.atr.AppID()}}, nil
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
// Installation IDs are globally unique per (App, account), so two distinct
// Apps installed for the same owner never collide here. The dedup exists for
// a configuration mistake, not an API property: cmd/app/main.go builds one
// manager per GITHUB_APP_IDS entry with no uniqueness check, and envconfig
// only validates that KMS_KEYS' length matches GITHUB_APP_IDS' — a duplicated
// App ID (e.g. GITHUB_APP_IDS=123,123) yields two managers wrapping the same
// installation, which would otherwise be double-counted here.
//
// If any manager fails to enumerate, every successful result — from that
// manager's own partial response and from every other manager — is still
// returned alongside the aggregate error: the list is real but incomplete,
// and a caller that needs exhaustiveness must not treat it as the whole set.
func (rr *roundRobin) GetAll(ctx context.Context, owner string) ([]Installation, error) {
	return rr.enumerate(ctx, owner, "GetAll", Manager.GetAll)
}

// GetAllFresh implements Manager. See the interface for the contract. It
// aggregates exactly as GetAll does.
func (rr *roundRobin) GetAllFresh(ctx context.Context, owner string) ([]Installation, error) {
	return rr.enumerate(ctx, owner, "GetAllFresh", Manager.GetAllFresh)
}

// enumerate runs one enumeration method across every manager, concatenating in
// managers order and deduplicating on installation ID. each takes the Manager
// before ctx because that is the shape of an interface method expression.
func (rr *roundRobin) enumerate(
	ctx context.Context,
	owner, label string,
	each func(Manager, context.Context, string) ([]Installation, error),
) ([]Installation, error) {
	out := make([]Installation, 0, len(rr.managers))
	var errs []error
	seen := make(map[int64]struct{}, len(rr.managers))

	for _, m := range rr.managers {
		if ctx.Err() != nil {
			// Bail rather than walking the remaining managers only to
			// collect N copies of the same cancellation error.
			errs = append(errs, ctx.Err())
			break
		}

		installs, err := each(m, ctx, owner)
		if err != nil {
			errs = append(errs, err)
			// installs may still be non-empty (a nested roundRobin or future
			// multi-install Manager can return a partial result alongside its
			// own error); collect it below rather than discarding it.
		}
		for _, in := range installs {
			if _, ok := seen[in.ID]; ok {
				continue
			}
			seen[in.ID] = struct{}{}
			out = append(out, in)
		}
	}

	if len(errs) > 0 {
		err := status.Errorf(codes.Unavailable, "enumerating installations for %q: %v", owner, errors.Join(errs...))
		clog.WarnContextf(ctx, "ghinstall: %s enumeration incomplete for %q: %d of %d managers failed; "+
			"callers requiring exhaustiveness must treat this as unknown: %v", label, owner, len(errs), len(rr.managers), err)
		return out, err
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
