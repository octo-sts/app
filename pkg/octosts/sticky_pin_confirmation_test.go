// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

// stickyReadBarrier makes both replicas read the original mapping before
// either can persist a replacement, without depending on goroutine timing.
type stickyReadBarrier struct {
	stickystore.Store
	reads atomic.Int32
	ready chan struct{}
}

func (s *stickyReadBarrier) Get(ctx context.Context, key string) (int64, bool, error) {
	id, ok, err := s.Store.Get(ctx, key)
	if n := s.reads.Add(1); n <= 2 {
		if n == 2 {
			close(s.ready)
		}
		select {
		case <-ctx.Done():
			return 0, false, ctx.Err()
		case <-s.ready:
		}
	}
	return id, ok, err
}

func TestStickyPinConfirmsIncompleteCachedCandidatesAcrossReplicas(t *testing.T) {
	for _, tc := range []struct {
		name string
		old  int64
	}{
		{name: "new assignment"},
		{name: "reassignment from excluded app", old: 21},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := "sticky-confirm-" + tc.name
			scope := owner + "/repo"
			const identity = "identity"
			// Select a route that hashes to 12 with the complete set, but
			// necessarily selects 11 when only that installation is visible.
			subject := "subject"
			for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
				subject = fmt.Sprintf("subject-%d", i)
			}
			key := routekey.Key(scope, identity, subject)
			store := &stickyReadBarrier{Store: memory.New(), ready: make(chan struct{})}
			if tc.old != 0 {
				if err := store.Put(ctx, key, tc.old, scope, identity, subject); err != nil {
					t.Fatal(err)
				}
			}
			full := []ghinstall.Installation{
				{ID: 11, AppID: 101},
				{ID: 12, AppID: 102},
				{ID: 21, AppID: 201},
			}
			managers := []*enumMgr{
				{installs: []ghinstall.Installation{full[0], full[2]}, freshInstalls: full},
				{installs: full},
			}
			apps := AppSet{
				Names: map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201},
				IDs:   map[int64]bool{101: true, 102: true, 201: true},
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
			type result struct {
				replica int
				id      int64
				err     error
			}
			results := make(chan result, len(managers))
			for i, mgr := range managers {
				go func() {
					// Distinct services model separate replicas, each with its
					// own cached installation view and confirmation flight.
					s := &sts{apps: apps, sticky: store}
					_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999)
					results <- result{replica: i, id: id, err: err}
				}()
			}
			for range managers {
				select {
				case got := <-results:
					if got.err != nil || got.id != 12 {
						t.Errorf("replica %d returned (%d, %v), want (12, nil) from the complete candidate set", got.replica, got.id, got.err)
					}
				case <-ctx.Done():
					t.Fatal("replicas did not complete: ", ctx.Err())
				}
			}
			if got := managers[0].freshCalls.Load(); got != 1 {
				t.Errorf("stale replica called GetAllFresh %d times, want 1", got)
			}
			if got := managers[1].freshCalls.Load(); got != 0 {
				t.Errorf("complete replica called GetAllFresh %d times, want 0", got)
			}
			if id, ok, err := store.Store.Get(ctx, key); err != nil || !ok || id != 12 {
				t.Errorf("persisted assignment = (%d, %t, %v), want (12, true, nil)", id, ok, err)
			}
		})
	}
}

func TestStickyPinFreshConfirmationFailurePreservesAssignment(t *testing.T) {
	for _, old := range []int64{0, 21} {
		t.Run(fmt.Sprintf("previous installation %d", old), func(t *testing.T) {
			ctx := context.Background()
			owner := fmt.Sprintf("sticky-confirm-error-%d", old)
			scope := owner + "/repo"
			const identity, subject = "identity", "subject"
			key := routekey.Key(scope, identity, subject)
			store := memory.New()
			if old != 0 {
				if err := store.Put(ctx, key, old, scope, identity, subject); err != nil {
					t.Fatal(err)
				}
			}
			installs := []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}}
			confirmErr := errors.New("fresh installation enumeration failed")
			mgr := &enumMgr{installs: installs, freshInstalls: installs, freshErr: confirmErr}
			s := &sts{
				sticky: store,
				apps: AppSet{
					Names: map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201},
					IDs:   map[int64]bool{101: true, 102: true, 201: true},
				},
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
			if _, _, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999); !errors.Is(err, confirmErr) {
				t.Errorf("getExchangeInstall error = %v, want %v", err, confirmErr)
			}
			if id, ok, err := store.Get(ctx, key); err != nil || id != old || ok != (old != 0) {
				t.Errorf("persisted assignment = (%d, %t, %v), want (%d, %t, nil)", id, ok, err, old, old != 0)
			}
			if got := mgr.freshCalls.Load(); got != 1 {
				t.Errorf("GetAllFresh called %d times, want 1", got)
			}
		})
	}
}

func TestStickyPinHonorsExistingEligibleAssignmentWithoutConfirmation(t *testing.T) {
	ctx := context.Background()
	const owner, scope, identity, subject = "sticky-valid", "sticky-valid/repo", "identity", "subject"
	key := routekey.Key(scope, identity, subject)
	store := memory.New()
	if err := store.Put(ctx, key, 11, scope, identity, subject); err != nil {
		t.Fatal(err)
	}
	mgr := &enumMgr{
		installs: []ghinstall.Installation{{ID: 11, AppID: 101}},
		freshErr: errors.New("fresh enumeration must not be needed for an existing eligible assignment"),
	}
	s := &sts{
		sticky: store,
		apps: AppSet{
			Names: map[string]int64{"ci-a": 101, "ci-b": 102},
			IDs:   map[int64]bool{101: true, 102: true},
		},
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
	if _, id, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999); err != nil || id != 11 {
		t.Errorf("getExchangeInstall = (%d, %v), want (11, nil)", id, err)
	}
	if got := mgr.freshCalls.Load(); got != 0 {
		t.Errorf("GetAllFresh called %d times, want 0", got)
	}
}

func TestStickyPinReassignmentReusesFreshConfirmation(t *testing.T) {
	ctx := context.Background()
	const owner, scope, identity, subject = "sticky-absent", "sticky-absent/repo", "identity", "subject"
	cacheKey := stickyAbsenceKey(owner, 21)
	pinMisses.Remove(cacheKey)
	t.Cleanup(func() { pinMisses.Remove(cacheKey) })
	key := routekey.Key(scope, identity, subject)
	store := memory.New()
	if err := store.Put(ctx, key, 21, scope, identity, subject); err != nil {
		t.Fatal(err)
	}
	// The same fresh walk proves the old installation is gone and the
	// eligible set has only one installed app. It need not be repeated.
	mgr := &enumMgr{
		installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
		freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}},
	}
	s := &sts{
		sticky: store,
		apps: AppSet{
			Names: map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201},
			IDs:   map[int64]bool{101: true, 102: true, 201: true},
		},
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
	if _, id, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999); err != nil || id != 11 {
		t.Errorf("getExchangeInstall = (%d, %v), want (11, nil)", id, err)
	}
	if id, ok, err := store.Get(ctx, key); err != nil || !ok || id != 11 {
		t.Errorf("persisted assignment = (%d, %t, %v), want (11, true, nil)", id, ok, err)
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times, want 1", got)
	}
}
