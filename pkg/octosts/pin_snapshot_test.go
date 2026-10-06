// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore"
	"github.com/octo-sts/app/pkg/stickystore/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// snapshotCachingMgr models a fresh walk repairing the cache while an earlier
// caller still holds a copy of the old installation list.
type snapshotCachingMgr struct {
	*enumMgr
	mu     sync.Mutex
	cached []ghinstall.Installation
}

func (m *snapshotCachingMgr) GetAll(context.Context, string) ([]ghinstall.Installation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.cached), nil
}

func (m *snapshotCachingMgr) GetAllFresh(context.Context, string) ([]ghinstall.Installation, error) {
	m.freshCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cached = slices.Clone(m.freshInstalls)
	return slices.Clone(m.cached), nil
}

// delayedStickySnapshot captures the first read's result, then delays its
// return until another request has confirmed candidates and written a pin.
type delayedStickySnapshot struct {
	stickystore.Store
	reads   atomic.Int32
	read    chan struct{}
	release chan struct{}
}

func (s *delayedStickySnapshot) Get(ctx context.Context, key string) (int64, bool, error) {
	id, ok, err := s.Store.Get(ctx, key)
	if s.reads.Add(1) == 1 {
		close(s.read)
		select {
		case <-ctx.Done():
			return 0, false, ctx.Err()
		case <-s.release:
		}
	}
	return id, ok, err
}

func TestStickyPinReusesConfirmedIncompleteCandidates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		old      int64
		reshadow bool
	}{
		{name: "new assignment"},
		{name: "reassignment from excluded app", old: 21},
		{name: "new assignment with re-shadowed cache", reshadow: true},
		{name: "reassignment with re-shadowed cache", old: 21, reshadow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			owner := "sticky-snapshot-" + tc.name
			scope := owner + "/repo"
			const identity = "identity"
			subject := "subject"
			for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
				subject = fmt.Sprintf("subject-%d", i)
			}
			key := routekey.Key(scope, identity, subject)
			store := &delayedStickySnapshot{
				Store:   memory.New(),
				read:    make(chan struct{}),
				release: make(chan struct{}),
			}
			if tc.old != 0 {
				if err := store.Put(ctx, key, tc.old, scope, identity, subject); err != nil {
					t.Fatal(err)
				}
			}
			// B is hidden by a stale negative-cache entry, while C is truly
			// absent. Confirmation discovers B but still records an incomplete
			// set because only two of the three matching Apps are installed.
			mgr := &snapshotCachingMgr{
				enumMgr: &enumMgr{freshInstalls: []ghinstall.Installation{
					{ID: 11, AppID: 101}, {ID: 12, AppID: 102}, {ID: 21, AppID: 201},
				}},
				cached: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}},
			}
			s := &sts{
				sticky: store,
				apps: AppSet{
					Names: map[string]int64{"ci-a": 101, "ci-b": 102, "ci-c": 103, "deploy": 201},
					IDs:   map[int64]bool{101: true, 102: true, 103: true, 201: true},
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
			type result struct {
				id  int64
				err error
			}
			delayed := make(chan result, 1)
			go func() {
				_, id, err := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999)
				delayed <- result{id: id, err: err}
			}()
			select {
			case <-store.read:
			case <-ctx.Done():
				t.Fatal("first request did not reach sticky.Get: ", ctx.Err())
			}
			_, firstID, firstErr := s.getExchangeInstall(ctx, poolOf(mgr), owner, scope, identity, subject, tp, nil, 999)
			if tc.reshadow {
				// An older lookup can finish after confirmation and re-arm a
				// negative entry. Use the confirmed snapshot even when rereading
				// the manager would again hide B.
				mgr.mu.Lock()
				mgr.cached = []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}}
				mgr.mu.Unlock()
			}
			close(store.release)
			if firstErr != nil || firstID != 12 {
				t.Errorf("confirming request = (%d, %v), want (12, nil)", firstID, firstErr)
			}
			select {
			case got := <-delayed:
				if got.err != nil || got.id != 12 {
					t.Errorf("delayed request = (%d, %v), want (12, nil) from the confirmed candidate set", got.id, got.err)
				}
			case <-ctx.Done():
				t.Fatal("delayed request did not complete: ", ctx.Err())
			}
			if got := mgr.freshCalls.Load(); got != 1 {
				t.Errorf("GetAllFresh called %d times, want 1 confirmation", got)
			}
			if id, ok, err := store.Store.Get(ctx, key); err != nil || !ok || id != 12 {
				t.Errorf("persisted assignment = (%d, %t, %v), want (12, true, nil)", id, ok, err)
			}
		})
	}
}

func TestStorelessPinReusesConfirmedIncompleteCandidates(t *testing.T) {
	ctx := context.Background()
	const owner, scope, identity = "storeless-snapshot", "storeless-snapshot/repo", "identity"
	subject := "subject"
	for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
		subject = fmt.Sprintf("subject-%d", i)
	}
	// Keep returning the old cached snapshot: another stale lookup could
	// re-shadow B, but the confirmed set remains valid for the throttle window.
	mgr := &enumMgr{
		installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
		freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
	}
	s := &sts{}
	eligible := map[int64]bool{101: true, 102: true, 103: true}
	for i := 0; i < 3; i++ {
		_, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible)
		if err != nil || id != 12 {
			t.Errorf("request %d = (%d, %v), want (12, nil) from the confirmed candidate set", i, id, err)
		}
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times, want 1 confirmation", got)
	}
}

func TestStickyPinRefreshesCandidatesAfterNewInstallation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const owner, scope, identity = "growing-snapshot", "growing-snapshot/repo", "identity"
	subject := "subject"
	for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
		subject = fmt.Sprintf("subject-%d", i)
	}
	eligible := map[int64]bool{101: true, 102: true, 103: true}
	onlyA := []ghinstall.Installation{{ID: 11, AppID: 101}}
	withB := []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}}
	warmMgr := &enumMgr{installs: onlyA, freshInstalls: onlyA}
	warm := &sts{}
	// A was the only installed match when this replica confirmed its set.
	if _, id, err := warm.getPinnedInstall(ctx, poolOf(warmMgr), owner, scope, identity, subject, true, eligible); err != nil || id != 11 {
		t.Fatalf("warming candidates = (%d, %v), want (11, nil)", id, err)
	}
	if got := warmMgr.freshCalls.Load(); got != 1 {
		t.Fatalf("warming called GetAllFresh %d times, want 1", got)
	}
	// B becomes installed before the confirmation TTL expires. Both replicas
	// now observe A+B, while C remains absent and the warm replica retains A.
	warmMgr.installs, warmMgr.freshInstalls = withB, withB
	coldMgr := &enumMgr{installs: withB, freshInstalls: withB}
	store := &stickyReadBarrier{Store: memory.New(), ready: make(chan struct{})}
	warm.sticky = store
	cold := &sts{sticky: store}
	type result struct {
		replica string
		id      int64
		err     error
	}
	results := make(chan result, 2)
	for _, replica := range []struct {
		name string
		s    *sts
		mgr  *enumMgr
	}{
		{name: "warm", s: warm, mgr: warmMgr},
		{name: "cold", s: cold, mgr: coldMgr},
	} {
		go func() {
			_, id, err := replica.s.getPinnedInstall(ctx, poolOf(replica.mgr), owner, scope, identity, subject, true, eligible)
			results <- result{replica: replica.name, id: id, err: err}
		}()
	}
	// The barrier makes both requests read the missing mapping before either
	// writes, so the expected owner must come from agreeing candidate sets.
	for range 2 {
		select {
		case got := <-results:
			if got.err != nil || got.id != 12 {
				t.Errorf("%s replica returned (%d, %v), want (12, nil)", got.replica, got.id, got.err)
			}
		case <-ctx.Done():
			t.Fatal("replicas did not complete: ", ctx.Err())
		}
	}
	if got := warmMgr.freshCalls.Load(); got != 2 {
		t.Errorf("warm replica called GetAllFresh %d times, want 2 including its original confirmation", got)
	}
	if got := coldMgr.freshCalls.Load(); got != 1 {
		t.Errorf("cold replica called GetAllFresh %d times, want 1", got)
	}
	key := routekey.Key(scope, identity, subject)
	if id, ok, err := store.Store.Get(ctx, key); err != nil || !ok || id != 12 {
		t.Errorf("persisted assignment = (%d, %t, %v), want (12, true, nil)", id, ok, err)
	}
	// A later stale enumeration must reuse the repaired A+B snapshot. Disable
	// sticky lookup so this assertion cannot pass via the persisted owner.
	warm.sticky = nil
	warmMgr.installs = onlyA
	for i := 0; i < 3; i++ {
		_, id, err := warm.getPinnedInstall(ctx, poolOf(warmMgr), owner, scope, identity, subject, true, eligible)
		if err != nil || id != 12 {
			t.Errorf("request after refresh %d = (%d, %v), want (12, nil)", i, id, err)
		}
	}
	if got := warmMgr.freshCalls.Load(); got != 2 {
		t.Errorf("warm replica called GetAllFresh %d times after reuse, want 2", got)
	}
}

func TestPinRefreshesCandidatesAfterInstallationReplacement(t *testing.T) {
	for _, tc := range []struct {
		name string
		inst ghinstall.Installation
	}{
		{name: "same app reinstalled", inst: ghinstall.Installation{ID: 13, AppID: 101}},
		{name: "different app installed", inst: ghinstall.Installation{ID: 12, AppID: 102}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := "replaced-snapshot-" + tc.name
			scope := owner + "/repo"
			eligible := map[int64]bool{101: true, 102: true, 103: true}
			mgr := &enumMgr{installs: []ghinstall.Installation{{ID: 11, AppID: 101}}}
			s := &sts{}
			if _, id, err := s.getPinnedInstall(t.Context(), poolOf(mgr), owner, scope, "identity", "subject", true, eligible); err != nil || id != 11 {
				t.Fatalf("warming candidates = (%d, %v), want (11, nil)", id, err)
			}
			// The count is unchanged, but this installation was absent from the
			// old confirmation and must not be hidden by its cached snapshot.
			mgr.installs = []ghinstall.Installation{tc.inst}
			for i := 0; i < 3; i++ {
				_, id, err := s.getPinnedInstall(t.Context(), poolOf(mgr), owner, scope, "identity", "subject", true, eligible)
				if err != nil || id != tc.inst.ID {
					t.Errorf("request %d = (%d, %v), want (%d, nil)", i, id, err, tc.inst.ID)
				}
			}
			if got := mgr.freshCalls.Load(); got != 2 {
				t.Errorf("GetAllFresh called %d times, want 2 including the original confirmation", got)
			}
		})
	}
}

func TestStickyPinCandidateRefreshFailurePreservesAssignment(t *testing.T) {
	ctx := t.Context()
	const owner, scope, identity = "growing-snapshot-error", "growing-snapshot-error/repo", "identity"
	subject := "subject"
	for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
		subject = fmt.Sprintf("subject-%d", i)
	}
	eligible := map[int64]bool{101: true, 102: true, 103: true}
	mgr := &enumMgr{installs: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 21, AppID: 201}}}
	s := &sts{}
	if _, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); err != nil || id != 11 {
		t.Fatalf("warming candidates = (%d, %v), want (11, nil)", id, err)
	}
	store := memory.New()
	key := routekey.Key(scope, identity, subject)
	if err := store.Put(ctx, key, 21, scope, identity, subject); err != nil {
		t.Fatal(err)
	}
	s.sticky = store
	mgr.installs = []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}, {ID: 21, AppID: 201}}
	refreshErr := errors.New("fresh installation enumeration failed")
	mgr.freshErr = refreshErr
	if _, _, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); !errors.Is(err, refreshErr) {
		t.Errorf("refresh error = %v, want %v", err, refreshErr)
	}
	if id, ok, err := store.Get(ctx, key); err != nil || !ok || id != 21 {
		t.Errorf("persisted assignment = (%d, %t, %v), want preserved (21, true, nil)", id, ok, err)
	}
	// A failed refresh must not mark the newly observed set as confirmed;
	// retry its confirmation before assigning an owner after recovery.
	mgr.freshErr = nil
	if _, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); err != nil || id != 12 {
		t.Errorf("retry = (%d, %v), want (12, nil)", id, err)
	}
	if got := mgr.freshCalls.Load(); got != 3 {
		t.Errorf("GetAllFresh called %d times, want 3 for warming, failure, and recovery", got)
	}
}

func TestPinRetainsCompleteRefreshedCandidates(t *testing.T) {
	for _, stickyAbsence := range []bool{false, true} {
		t.Run(fmt.Sprintf("sticky absence %t", stickyAbsence), func(t *testing.T) {
			ctx := t.Context()
			owner := fmt.Sprintf("complete-refreshed-snapshot-%t", stickyAbsence)
			scope := owner + "/repo"
			const identity = "identity"
			subjectForC := func(prefix string) string {
				for i := 0; ; i++ {
					subject := fmt.Sprintf("%s-%d", prefix, i)
					if routekey.Index(scope, identity, subject, 3) == 2 {
						return subject
					}
				}
			}
			subject := subjectForC("subject")
			eligible := map[int64]bool{101: true, 102: true, 103: true}
			onlyA := []ghinstall.Installation{{ID: 11, AppID: 101}}
			complete := []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}, {ID: 13, AppID: 103}}
			mgr := &enumMgr{installs: onlyA, freshInstalls: onlyA}
			s := &sts{}
			if _, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); err != nil || id != 11 {
				t.Fatalf("warming candidates = (%d, %v), want (11, nil)", id, err)
			}
			mgr.freshInstalls = complete
			if stickyAbsence {
				// Confirming an absent sticky owner can discover the complete
				// set before the normal incomplete-candidate check is reached.
				store := memory.New()
				key := routekey.Key(scope, identity, subject)
				if err := store.Put(ctx, key, 21, scope, identity, subject); err != nil {
					t.Fatal(err)
				}
				absKey := stickyAbsenceKey(owner, 21)
				pinMisses.Remove(absKey)
				t.Cleanup(func() { pinMisses.Remove(absKey) })
				s.sticky = store
			} else {
				// Observing B invalidates the old A confirmation; the fresh
				// walk also discovers C, making the result complete.
				mgr.installs = complete[:2]
			}
			if _, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); err != nil || id != 13 {
				t.Errorf("refresh = (%d, %v), want (13, nil)", id, err)
			}
			// A delayed enumeration of A must reuse the now-complete snapshot.
			// Use new route keys to avoid passing through an existing sticky pin.
			mgr.installs = onlyA
			for i := 0; i < 3; i++ {
				newSubject := subjectForC(fmt.Sprintf("new-route-%d", i))
				_, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, newSubject, true, eligible)
				if err != nil || id != 13 {
					t.Errorf("new route %d = (%d, %v), want (13, nil)", i, id, err)
				}
			}
			if got := mgr.freshCalls.Load(); got != 2 {
				t.Errorf("GetAllFresh called %d times, want 2 including the original confirmation", got)
			}
		})
	}
}

func TestPinConfirmationReplacesStaleCandidates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fresh []ghinstall.Installation
		id    int64
		code  codes.Code
	}{
		{name: "shrinking set", fresh: []ghinstall.Installation{{ID: 11, AppID: 101}}, id: 11, code: codes.OK},
		{name: "empty set", fresh: []ghinstall.Installation{}, code: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const owner, scope, identity = "shrinking-snapshot", "shrinking-snapshot/repo", "identity"
			subject := "subject"
			for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
				subject = fmt.Sprintf("subject-%d", i)
			}
			mgr := &enumMgr{
				installs:      []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
				freshInstalls: tc.fresh,
			}
			s := &sts{}
			for i := 0; i < 2; i++ {
				_, id, err := s.getPinnedInstall(t.Context(), poolOf(mgr), owner, scope, identity, subject, true, map[int64]bool{101: true, 102: true, 103: true})
				if id != tc.id || status.Code(err) != tc.code {
					t.Errorf("request %d = (%d, %v), want (%d, %v)", i, id, err, tc.id, tc.code)
				}
			}
			if got := mgr.freshCalls.Load(); got != 1 {
				t.Errorf("GetAllFresh called %d times, want 1 confirmation", got)
			}
		})
	}
}

func TestCanceledPinConfirmationRetainsCandidates(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const owner, scope, identity = "canceled-snapshot", "canceled-snapshot/repo", "identity"
	subject := "subject"
	for i := 0; routekey.Index(scope, identity, subject, 2) != 1; i++ {
		subject = fmt.Sprintf("subject-%d", i)
	}
	gate := make(chan struct{})
	mgr := &enumMgr{
		installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
		freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
		freshGate:     gate,
	}
	s := &sts{}
	eligible := map[int64]bool{101: true, 102: true, 103: true}
	canceled, stop := context.WithCancel(ctx)
	stop()
	_, _, err := s.getPinnedInstall(canceled, poolOf(mgr), owner, scope, identity, subject, true, eligible)
	// The canceled request returns before the detached walk may finish.
	close(gate)
	if status.Code(err) != codes.Canceled {
		t.Fatalf("canceled request error = %v, want Canceled", err)
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, ok := s.pinCandidates.Get(pinMissKey(owner, eligible)); ok {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("detached confirmation did not retain candidates: ", ctx.Err())
		case <-ticker.C:
		}
	}
	_, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible)
	if err != nil || id != 12 {
		t.Errorf("retry = (%d, %v), want (12, nil) from the detached confirmation", id, err)
	}
	if got := mgr.freshCalls.Load(); got != 1 {
		t.Errorf("GetAllFresh called %d times, want 1 confirmation", got)
	}
}

func TestConfirmedPinCandidatesStayWithinService(t *testing.T) {
	for _, id := range []int64{11, 21} {
		// Both services have the same owner and App IDs; their independently
		// confirmed installation IDs must remain within their own service.
		s := &sts{}
		mgr := &enumMgr{installs: []ghinstall.Installation{{ID: id, AppID: 101}}}
		for i := 0; i < 2; i++ {
			_, got, err := s.getPinnedInstall(t.Context(), poolOf(mgr), "shared-owner", "shared-owner/repo", "identity", "subject", true, map[int64]bool{101: true, 102: true})
			if err != nil || got != id {
				t.Errorf("service with installation %d, request %d = (%d, %v)", id, i, got, err)
			}
		}
		if got := mgr.freshCalls.Load(); got != 1 {
			t.Errorf("service with installation %d called GetAllFresh %d times, want 1", id, got)
		}
	}
}

func TestStickyAbsenceConfirmationReplacesOlderCandidateSnapshot(t *testing.T) {
	ctx := t.Context()
	const owner, scope, identity, subject = "sticky-empty-snapshot", "sticky-empty-snapshot/repo", "identity", "subject"
	absKey := stickyAbsenceKey(owner, 21)
	pinMisses.Remove(absKey)
	t.Cleanup(func() { pinMisses.Remove(absKey) })
	store := memory.New()
	s := &sts{sticky: store}
	mgr := &enumMgr{
		installs:      []ghinstall.Installation{{ID: 11, AppID: 101}},
		freshInstalls: []ghinstall.Installation{{ID: 11, AppID: 101}, {ID: 12, AppID: 102}},
	}
	eligible := map[int64]bool{101: true, 102: true, 103: true}
	// Retain an earlier nonempty snapshot, then require reassignment of a
	// sticky installation missing from both cached and fresh enumeration.
	if _, _, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible); err != nil {
		t.Fatal("warming confirmed candidates: ", err)
	}
	key := routekey.Key(scope, identity, subject)
	if err := store.Put(ctx, key, 21, scope, identity, subject); err != nil {
		t.Fatal(err)
	}
	mgr.freshInstalls = []ghinstall.Installation{}
	before := mgr.freshCalls.Load()
	_, id, err := s.getPinnedInstall(ctx, poolOf(mgr), owner, scope, identity, subject, true, eligible)
	if id != 0 || status.Code(err) != codes.FailedPrecondition {
		t.Errorf("reassignment = (%d, %v), want (0, FailedPrecondition) after empty confirmation", id, err)
	}
	if calls := mgr.freshCalls.Load() - before; calls != 1 {
		t.Errorf("reassignment called GetAllFresh %d times, want 1", calls)
	}
	if id, ok, err := store.Get(ctx, key); err != nil || !ok || id != 21 {
		t.Errorf("persisted assignment = (%d, %t, %v), want preserved (21, true, nil)", id, ok, err)
	}
}
