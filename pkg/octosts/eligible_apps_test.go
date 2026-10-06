// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/octo-sts/app/pkg/ghinstall"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestEligibleAppsScopesSelectorsToConfiguredPool(t *testing.T) {
	s := &sts{apps: AppSet{
		Names: map[string]int64{"ci-a": 101, "ci-b": 102, "ci-remote": 103, "deploy": 201},
		IDs:   map[int64]bool{101: true, 102: true, 103: true, 201: true},
	}}
	local := map[int64]bool{101: true, 102: true, 201: true}
	for _, tc := range []struct {
		name    string
		app     string
		pattern string
		members map[int64]bool
		want    map[int64]bool
		code    codes.Code
	}{
		{name: "pattern includes all configured local matches", pattern: "ci-.*", members: local, want: map[int64]bool{101: true, 102: true}},
		{name: "local name", app: "ci-a", members: local, want: map[int64]bool{101: true}},
		{name: "local numeric ID", app: "102", members: local, want: map[int64]bool{102: true}},
		{name: "remote name", app: "ci-remote", members: local, code: codes.FailedPrecondition},
		{name: "remote numeric ID", app: "103", members: local, code: codes.FailedPrecondition},
		{name: "remote-only pattern", pattern: "ci-remote", members: local, code: codes.FailedPrecondition},
		{name: "unpinned", members: local},
		{name: "empty pool", pattern: "ci-.*", members: map[int64]bool{}, code: codes.FailedPrecondition},
		{name: "empty pool unpinned", members: map[int64]bool{}},
		{name: "nil membership fails closed for pattern", pattern: "ci-.*", code: codes.FailedPrecondition},
		{name: "nil membership fails closed for named app", app: "ci-remote", code: codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tp := &TrustPolicy{Issuer: "https://example.com", Subject: "subject", App: tc.app, AppPattern: tc.pattern}
			if err := tp.Compile(); err != nil {
				t.Fatal(err)
			}
			// No manager is needed: eligibility must depend on configured
			// membership, including apps with unavailable installations.
			pool := &ghinstall.OrgPool{AppIDs: tc.members}
			got, err := s.eligibleApps(pool, "local-org", tp)
			if status.Code(err) != tc.code {
				t.Fatalf("eligibleApps error = %v, want code %v", err, tc.code)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("eligibleApps mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
