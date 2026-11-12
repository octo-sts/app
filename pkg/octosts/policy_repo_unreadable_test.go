// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/ghinstall"
)

// newUnreadableRepoTransport is an installation that GitHub refuses a token for
// the policy repository, as it does for an App installed on selected
// repositories that do not include it.
func newUnreadableRepoTransport(t *testing.T) *ghinstallation.AppsTransport {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/app/installations/{appID}/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"There is at least one repository that does not exist or is not accessible to the parent installation."}`))
	})
	mux.HandleFunc("/repos/{org}/{repo}/contents/.github/chainguard/{identity}", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("policy read without a token: %s", r.URL.Path)
	})
	return newAppsTransport(t, &fakeGitHub{mux: mux})
}

func newReadablePolicyTransport(t *testing.T) *ghinstallation.AppsTransport {
	t.Helper()
	const policy = "issuer: https://example.com\nsubject: example\n"
	return newPolicyReadTransport(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(github.RepositoryContent{
			Content:  new(base64.StdEncoding.EncodeToString([]byte(policy))),
			Type:     new("file"),
			Encoding: new("base64"),
		})
	})
}

func TestPolicyReadTriesNextAppWhenRepoUnreadable(t *testing.T) {
	key := freshTPKey(t, "unreadable-then-readable")
	unreadable := newUnreadableRepoTransport(t)
	pool := &ghinstall.OrgPool{
		M: &sequentialInstallMgr{
			transports: []*ghinstallation.AppsTransport{unreadable, newReadablePolicyTransport(t)},
		},
		AppCount: 2,
	}

	s := &sts{}
	_, id, err := s.lookupTrustPolicyWithRetry(t.Context(), pool, unreadable, 1234, key.owner, key.owner+"/"+key.repo, key.identity, key, &TrustPolicy{})
	if err != nil {
		t.Fatalf("lookupTrustPolicyWithRetry: %v", err)
	}
	if id != 1235 {
		t.Errorf("policy read by installation %d, want 1235", id)
	}
}

func TestPolicyReadUnreadableEverywhere(t *testing.T) {
	key := freshTPKey(t, "unreadable-everywhere")
	first := newUnreadableRepoTransport(t)
	pool := &ghinstall.OrgPool{
		M: &sequentialInstallMgr{
			transports: []*ghinstallation.AppsTransport{first, newUnreadableRepoTransport(t)},
		},
		AppCount: 2,
	}

	s := &sts{}
	_, _, err := s.lookupTrustPolicyWithRetry(t.Context(), pool, first, 1234, key.owner, key.owner+"/"+key.repo, key.identity, key, &TrustPolicy{})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v (%v), want FailedPrecondition", got, err)
	}
	// The failure says nothing about the policy, so it must not be cached as
	// absent: once an installation can read the repository, the next exchange
	// has to read it.
	if _, ok := trustPolicies.Get(key); ok {
		t.Error("an unreadable repository was cached for the policy")
	}
}

func TestIsUnreadableRepoMint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		header http.Header
		want   bool
	}{
		{name: "422", status: http.StatusUnprocessableEntity, want: true},
		{name: "rate-limited 422", status: http.StatusUnprocessableEntity, header: http.Header{"X-Ratelimit-Remaining": {"0"}}, want: false},
		{name: "403", status: http.StatusForbidden, want: false},
		{name: "404", status: http.StatusNotFound, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &ghinstallation.HTTPError{Response: &http.Response{StatusCode: tc.status, Header: tc.header}}
			if got := isUnreadableRepoMint(err); got != tc.want {
				t.Errorf("isUnreadableRepoMint = %v, want %v", got, tc.want)
			}
		})
	}
}
