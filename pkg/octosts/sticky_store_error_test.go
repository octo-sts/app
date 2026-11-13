// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore/memory"
)

// failingStore wraps a memory store and fails Get or Put on demand, counting
// the Put calls that reach the backend.
type failingStore struct {
	*memory.Store
	getErr error
	putErr error
	puts   atomic.Int32
}

func (f *failingStore) Get(ctx context.Context, key string) (int64, bool, error) {
	if f.getErr != nil {
		return 0, false, f.getErr
	}
	return f.Store.Get(ctx, key)
}

func (f *failingStore) Put(ctx context.Context, key string, id int64, scope, identity, subject string) error {
	f.puts.Add(1)
	if f.putErr != nil {
		return f.putErr
	}
	return f.Store.Put(ctx, key, id, scope, identity, subject)
}

// TestStickyGetErrorFailsClosed covers #1877: a sticky store read error on a
// checks:write exchange must not route to whichever App the pool picks, and
// must not overwrite the persisted mapping with that pick. Either would move
// the key off the App that owns its check runs.
func TestStickyGetErrorFailsClosed(t *testing.T) {
	ctx := context.Background()
	appNames := map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201}
	appIDs := map[int64]bool{101: true, 102: true, 201: true}
	checksWrite := github.InstallationPermissions{Checks: github.Ptr("write")}
	key := routekey.Key("org/repo", "id", "subj")

	compile := func(t *testing.T, tp *TrustPolicy) *TrustPolicy {
		t.Helper()
		tp.Issuer = "https://example.com"
		tp.Subject = "subject"
		if err := tp.Compile(); err != nil {
			t.Fatalf("Compile: %v", err)
		}
		return tp
	}

	tests := []struct {
		name string
		tp   *TrustPolicy
	}{
		{name: "unpinned", tp: &TrustPolicy{Permissions: checksWrite}},
		{name: "pinned", tp: &TrustPolicy{AppPattern: "ci-.*", Permissions: checksWrite}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// pool.M.Get picks install 11, so a fallback would visibly move
			// the key off the persisted install 12.
			mgr := &enumMgr{installs: []ghinstall.Installation{
				{ID: 11, AppID: 101},
				{ID: 12, AppID: 102},
			}}
			store := &failingStore{Store: memory.New()}
			if err := store.Store.Put(ctx, key, 12, "org/repo", "id", "subj"); err != nil {
				t.Fatal(err)
			}
			store.getErr = errors.New("firestore: unavailable")
			s := &sts{apps: AppSet{Names: appNames, IDs: appIDs}, sticky: store}
			before := testutil.ToFloat64(stickyStoreErrorsTotal.WithLabelValues("get"))

			_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), "org", "org/repo", "id", "subj", compile(t, tc.tp), nil, 999)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("got (%d, %v), want Unavailable", id, err)
			}
			if got := store.puts.Load(); got != 0 {
				t.Errorf("Put called %d times, want 0 (mapping must not be overwritten)", got)
			}
			if got, ok, _ := store.Store.Get(ctx, key); !ok || got != 12 {
				t.Errorf("sticky = (%d, %t), want preserved (12, true)", got, ok)
			}
			if got := mgr.getCalls.Load(); got != 0 {
				t.Errorf("pool.M.Get called %d times, want 0 (no reroute)", got)
			}
			if got := testutil.ToFloat64(stickyStoreErrorsTotal.WithLabelValues("get")) - before; got != 1 {
				t.Errorf("get error metric rose by %v, want 1", got)
			}
		})
	}

	t.Run("non-checks:write ignores the store", func(t *testing.T) {
		store := &failingStore{Store: memory.New(), getErr: errors.New("firestore: unavailable")}
		s := &sts{sticky: store}
		mgr := &enumMgr{installs: []ghinstall.Installation{{ID: 11, AppID: 101}}}
		_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), "org", "org/repo", "id", "subj", compile(t, &TrustPolicy{}), nil, 999)
		if err != nil || id != 999 {
			t.Fatalf("got (%d, %v), want the read installation (999, nil)", id, err)
		}
	})

	t.Run("put error keeps the exchange and counts it", func(t *testing.T) {
		store := &failingStore{Store: memory.New(), putErr: errors.New("firestore: unavailable")}
		s := &sts{sticky: store}
		mgr := &enumMgr{installs: []ghinstall.Installation{{ID: 11, AppID: 101}}}
		before := testutil.ToFloat64(stickyStoreErrorsTotal.WithLabelValues("put"))

		_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), "org", "org/repo", "id", "subj", compile(t, &TrustPolicy{Permissions: checksWrite}), nil, 999)
		if err != nil || id != 11 {
			t.Fatalf("got (%d, %v), want (11, nil)", id, err)
		}
		if got := store.puts.Load(); got != 1 {
			t.Errorf("Put called %d times, want 1", got)
		}
		if got := testutil.ToFloat64(stickyStoreErrorsTotal.WithLabelValues("put")) - before; got != 1 {
			t.Errorf("put error metric rose by %v, want 1", got)
		}
	})
}
