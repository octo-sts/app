// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v75/github"
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
	if v, ok := m.cache.Get(owner); ok {
		clog.InfoContextf(ctx, "found installation in cache for %s", owner)
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
				m.cache.Add(owner, installID)
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
	idx := rr.counter.Add(1) % uint64(len(rr.managers))
	return rr.managers[idx].Get(ctx, owner)
}
