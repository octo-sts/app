// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"errors"
	"testing"

	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/routekey"
	"github.com/octo-sts/app/pkg/stickystore/memory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestChecksWritePinScopesCompletenessToOrgPool(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sticky   bool
		old      int64
		failed   bool
		wildcard bool
	}{
		{name: "storeless healthy pool"},
		{name: "storeless unrelated lookup failure", failed: true},
		{name: "new sticky assignment", sticky: true, failed: true},
		{name: "sticky reassignment", sticky: true, old: 31, failed: true},
		{name: "wildcard pool", failed: true, wildcard: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			owner := "pool-complete-" + tc.name
			scope := owner + "/repo"
			const identity, subject = "identity", "subject"
			// The selected pool has ci-a, deploy, and legacy. Only ci-a
			// matches the pin; ci-b is configured for another organization.
			mgr := &enumMgr{installs: []ghinstall.Installation{
				{ID: 11, AppID: 101}, {ID: 31, AppID: 301},
			}}
			if tc.failed {
				mgr.err = errors.New("deploy installation lookup failed")
			} else {
				mgr.installs = append(mgr.installs, ghinstall.Installation{ID: 21, AppID: 201})
			}
			pool := &ghinstall.OrgPool{M: mgr, AppCount: 3, AppIDs: map[int64]bool{101: true, 201: true, 301: true}}
			poolKey := owner
			if tc.wildcard {
				poolKey = ghinstall.WildcardOrg
			}
			router := ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{
				poolKey:     pool,
				"other-org": {M: &enumMgr{installs: []ghinstall.Installation{{ID: 12, AppID: 102}}}, AppCount: 1, AppIDs: map[int64]bool{102: true}},
			})
			selected, err := router.GetPool(owner)
			if err != nil {
				t.Fatal(err)
			}
			s := &sts{apps: AppSet{
				Names: map[string]int64{"ci-a": 101, "ci-b": 102, "deploy": 201, "legacy": 301},
				IDs:   map[int64]bool{101: true, 102: true, 201: true, 301: true},
			}}
			key := routekey.Key(scope, identity, subject)
			if tc.sticky {
				s.sticky = memory.New()
				if tc.old != 0 {
					if err := s.sticky.Put(ctx, key, tc.old, scope, identity, subject); err != nil {
						t.Fatal(err)
					}
				}
			}
			tp := &TrustPolicy{
				Issuer: "https://example.com", Subject: subject, AppPattern: "ci-.*",
				Permissions: github.InstallationPermissions{Checks: github.Ptr("write")},
			}
			if err := tp.Compile(); err != nil {
				t.Fatal(err)
			}
			if _, id, err := s.getExchangeInstall(ctx, selected, owner, scope, identity, subject, tp, nil, 999); err != nil || id != 11 {
				t.Errorf("getExchangeInstall = (%d, %v), want (11, nil) from the complete local matching set", id, err)
			}
			if got := mgr.freshCalls.Load(); got != 0 {
				t.Errorf("GetAllFresh called %d times, want 0 for a complete local matching set", got)
			}
			if tc.sticky {
				if id, ok, err := s.sticky.Get(ctx, key); err != nil || !ok || id != 11 {
					t.Errorf("persisted assignment = (%d, %t, %v), want (11, true, nil)", id, ok, err)
				}
			}
		})
	}
}

func TestChecksWritePinRejectsIncompleteLocalCandidates(t *testing.T) {
	for _, sticky := range []bool{false, true} {
		name := "storeless"
		if sticky {
			name = "sticky"
		}
		t.Run(name, func(t *testing.T) {
			lookupErr := errors.New("ci-b installation lookup failed")
			mgr := &enumMgr{installs: []ghinstall.Installation{{ID: 11, AppID: 101}}, err: lookupErr}
			pool := &ghinstall.OrgPool{M: mgr, AppCount: 2, AppIDs: map[int64]bool{101: true, 102: true}}
			s := &sts{apps: AppSet{
				Names: map[string]int64{"ci-a": 101, "ci-b": 102, "ci-remote": 103},
				IDs:   map[int64]bool{101: true, 102: true, 103: true},
			}}
			if sticky {
				s.sticky = memory.New()
			}
			tp := &TrustPolicy{
				Issuer: "https://example.com", Subject: "subject", AppPattern: "ci-.*",
				Permissions: github.InstallationPermissions{Checks: github.Ptr("write")},
			}
			if err := tp.Compile(); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.getExchangeInstall(t.Context(), pool, "pool-incomplete", "pool-incomplete/repo", "identity", "subject", tp, nil, 999); !errors.Is(err, lookupErr) {
				t.Errorf("getExchangeInstall error = %v, want %v when a local matching App is missing", err, lookupErr)
			}
			if sticky {
				key := routekey.Key("pool-incomplete/repo", "identity", "subject")
				if id, ok, err := s.sticky.Get(t.Context(), key); err != nil || ok {
					t.Errorf("persisted assignment = (%d, %t, %v), want no assignment after incomplete enumeration", id, ok, err)
				}
			}
		})
	}
}

func TestPinRejectsAppConfiguredOnlyInAnotherOrgPool(t *testing.T) {
	mgr := &enumMgr{err: errors.New("unrelated local App lookup failed")}
	pool := &ghinstall.OrgPool{M: mgr, AppCount: 1, AppIDs: map[int64]bool{101: true}}
	s := &sts{apps: AppSet{
		Names: map[string]int64{"ci-a": 101, "ci-b": 102},
		IDs:   map[int64]bool{101: true, 102: true},
	}}
	tp := &TrustPolicy{Issuer: "https://example.com", Subject: "subject", App: "ci-b"}
	if err := tp.Compile(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.getExchangeInstall(t.Context(), pool, "pool-exact", "pool-exact/repo", "identity", "subject", tp, nil, 999); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("getExchangeInstall error = %v, want FailedPrecondition for an App outside the selected pool", err)
	}
	if got := mgr.freshCalls.Load(); got != 0 {
		t.Errorf("GetAllFresh called %d times, want 0 for an App outside the selected pool", got)
	}
}
