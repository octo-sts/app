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

// roundRobin distributes requests across managers using an atomic counter.
// It does not use scope or identity for routing, so different callers with
// the same (scope, identity) may land on different apps. Use this only when
// the caller's trust policy does not require checks:write — i.e., when there
// is no GitHub check-run ownership constraint.
type roundRobin struct {
	managers []Manager
	counter  atomic.Uint64
}

// NewRoundRobin creates a Manager that distributes requests across the given
// managers using an atomic round-robin counter.
//
// Use this when the trust policy does NOT require checks:write. For policies
// that do require checks:write, use NewMultiManager (consistent hashing) so
// that the same GitHub App always handles a given (scope, identity) and can
// therefore update check runs it previously created.
func NewRoundRobin(managers []Manager) Manager {
	if len(managers) == 0 {
		panic("ghinstall: NewRoundRobin requires at least one manager")
	}
	return &roundRobin{managers: managers}
}

func (rr *roundRobin) Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error) {
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

func (rr *multiManager) Get(ctx context.Context, owner, scope, identity string) (*ghinstallation.AppsTransport, int64, error) {
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
