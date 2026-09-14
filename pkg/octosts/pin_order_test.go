// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

func TestChecksWritePinIgnoresConfiguredAppOrder(t *testing.T) {
	ctx := context.Background()
	const owner, scope, identity = "pin-order", "pin-order/repo", "identity"
	apps := AppSet{
		Names: map[string]int64{"ci-a": 101, "ci-b": 102, "ci-c": 103, "deploy": 201},
		IDs:   map[int64]bool{101: true, 102: true, 103: true, 201: true},
	}
	tp := &TrustPolicy{
		Issuer:      "https://example.com",
		Subject:     "subject",
		AppPattern:  "ci-.*",
		Permissions: github.InstallationPermissions{Checks: github.Ptr("write")},
	}
	if err := tp.Compile(); err != nil {
		t.Fatal(err)
	}
	installs := []ghinstall.Installation{
		{ID: 11, AppID: 101},
		{ID: 12, AppID: 102},
		{ID: 13, AppID: 103},
		{ID: 21, AppID: 201},
	}
	// GetAll follows configured App order. Model deployments that preserve
	// every App and installation, but reverse or permute the configuration.
	orders := []struct {
		name     string
		installs []ghinstall.Installation
	}{
		{name: "original", installs: installs},
		{name: "reversed", installs: []ghinstall.Installation{installs[3], installs[2], installs[1], installs[0]}},
		{name: "permuted", installs: []ghinstall.Installation{installs[1], installs[3], installs[0], installs[2]}},
	}
	const routes = 32
	var original [routes]int64
	originalService := &sts{apps: apps}
	originalPool := poolOf(&enumMgr{installs: slices.Clone(installs)})
	for i := range routes {
		subject := fmt.Sprintf("subject-%d", i)
		_, id, err := originalService.getExchangeInstall(ctx, originalPool, owner, scope, identity, subject, tp, nil, 999)
		if err != nil {
			t.Fatalf("original route %q: %v", subject, err)
		}
		original[i] = id
	}
	for _, order := range orders {
		t.Run(order.name, func(t *testing.T) {
			s := &sts{apps: apps}
			mgr := &enumMgr{installs: order.installs}
			originalInstalls := slices.Clone(mgr.installs)
			pool := poolOf(mgr)
			seen := make(map[int64]bool)
			changed := 0
			for i := range routes {
				subject := fmt.Sprintf("subject-%d", i)
				_, id, err := s.getExchangeInstall(ctx, pool, owner, scope, identity, subject, tp, nil, 999)
				if err != nil {
					t.Fatalf("route %q: %v", subject, err)
				}
				if id != 11 && id != 12 && id != 13 {
					t.Fatalf("route %q selected installation %d outside the pin", subject, id)
				}
				seen[id] = true
				if original[i] != id {
					changed++
				}
			}
			if changed != 0 {
				t.Errorf("reordering the same Apps changed ownership for %d of %d routes", changed, routes)
			}
			if len(seen) != 3 {
				t.Errorf("routes selected %d eligible installations, want all 3", len(seen))
			}
			if got := mgr.freshCalls.Load(); got != 0 {
				t.Errorf("GetAllFresh called %d times for a complete installation set, want 0", got)
			}
			if !slices.Equal(mgr.installs, originalInstalls) {
				t.Errorf("routing mutated the manager's installation list: got %v, want %v", mgr.installs, originalInstalls)
			}
		})
	}
}

func TestStickyChecksWritePinAgreesAcrossConfiguredAppOrders(t *testing.T) {
	const owner, scope, identity = "sticky-pin-order", "sticky-pin-order/repo", "identity"
	apps := AppSet{
		Names: map[string]int64{"ci-a": 101, "ci-b": 102},
		IDs:   map[int64]bool{101: true, 102: true},
	}
	tp := &TrustPolicy{
		Issuer:      "https://example.com",
		Subject:     "subject",
		AppPattern:  "ci-.*",
		Permissions: github.InstallationPermissions{Checks: github.Ptr("write")},
	}
	if err := tp.Compile(); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		subject := fmt.Sprintf("subject-%d", i)
		t.Run(subject, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			store := &stickyReadBarrier{Store: memory.New(), ready: make(chan struct{})}
			managers := []*enumMgr{
				{installs: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}}},
				{installs: []ghinstall.Installation{{ID: 12, AppID: 102}, {ID: 11, AppID: 101}}},
			}
			type result struct {
				id  int64
				err error
			}
			results := make(chan result, len(managers))
			for _, mgr := range managers {
				go func() {
					s := &sts{apps: apps, sticky: store}
					_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999)
					results <- result{id: id, err: err}
				}()
			}
			var first int64
			for range managers {
				select {
				case got := <-results:
					if got.err != nil {
						t.Fatalf("exchange: %v", got.err)
					}
					if got.id != 11 && got.id != 12 {
						t.Fatalf("selected installation %d outside the pin", got.id)
					}
					if first == 0 {
						first = got.id
					} else if got.id != first {
						t.Errorf("replicas with reordered Apps assigned installations %d and %d to the same route", first, got.id)
					}
				case <-ctx.Done():
					t.Fatal("replicas did not complete: ", ctx.Err())
				}
			}
			key := routekey.Key(scope, identity, subject)
			if id, ok, err := store.Store.Get(ctx, key); err != nil || !ok || id != first {
				t.Errorf("persisted assignment = (%d, %t, %v), want (%d, true, nil)", id, ok, err, first)
			}
		})
	}
}
