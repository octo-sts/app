// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"fmt"
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
type Manager interface {
	Get(ctx context.Context, owner string) (*ghinstallation.AppsTransport, int64, error)
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
func (m *manager) Get(ctx context.Context, owner string) (*ghinstallation.AppsTransport, int64, error) {
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

type roundRobin struct {
	managers []Manager
	counter  atomic.Uint64
}

// NewRoundRobin creates a Manager that distributes requests across the given managers.
func NewRoundRobin(managers []Manager) Manager {
	return &roundRobin{managers: managers}
}

func (rr *roundRobin) Get(ctx context.Context, owner string) (*ghinstallation.AppsTransport, int64, error) {
	primary_app_index := uint64(0)

	// Select a random application index to use for this request. This ensures
	// that if one app is not installed for a given owner, we will fall back
	// to a different app instead of always hitting the same one.
	random_index := rr.counter.Add(1) % uint64(len(rr.managers))

	atr, id, err := rr.managers[random_index].Get(ctx, owner)
	if err == nil {
		return atr, id, nil
	}
	// If the selected manager is already the fallback (first), return the error as-is.
	if random_index == primary_app_index {
		return nil, int64(primary_app_index), err
	}
	// If the app is not installed for this owner, fall back to the first app.
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		clog.InfoContextf(ctx, "app not installed for %q, falling back to first app", owner)
		return rr.managers[primary_app_index].Get(ctx, owner)
	}
	return nil, int64(primary_app_index), err
}
