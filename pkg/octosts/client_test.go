// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"bytes"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestNewGitHubClientBaseURL pins the base URL every client in this package is
// built with. The expected strings were determined empirically from go-github
// v88 rather than assumed: WithEnterpriseURLs appends /api/v3/ when the given
// URL does not already end in it, and always leaves a trailing slash.
//
// This exists because an earlier revision of the org-allowlist read built its
// own client without the enterprise option, so on a GitHub Enterprise Server
// deployment the read went to api.github.com, failed, and was classified as
// "this installation cannot see .github" — which silently disabled issuer
// enforcement for the whole deployment.
func TestNewGitHubClientBaseURL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		baseURL string
		want    string
	}{{
		name:    "empty base URL uses the github.com default",
		baseURL: "",
		want:    "https://api.github.com/",
	}, {
		name:    "enterprise host gains the /api/v3/ suffix",
		baseURL: "https://ghes.example.com",
		want:    "https://ghes.example.com/api/v3/",
	}, {
		name:    "enterprise API endpoint is preserved",
		baseURL: "https://ghes.example.com/api/v3/",
		want:    "https://ghes.example.com/api/v3/",
	}, {
		name:    "enterprise API endpoint without a trailing slash",
		baseURL: "https://ghes.example.com/api/v3",
		want:    "https://ghes.example.com/api/v3/",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := newGitHubClient(http.DefaultTransport, tc.baseURL)
			if err != nil {
				t.Fatalf("newGitHubClient() = %v", err)
			}
			if got := client.BaseURL(); got != tc.want {
				t.Errorf("BaseURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGitHubClientHasOneConstructor enforces that newGitHubClient is the only
// place this package builds a GitHub client.
//
// It is a convention test rather than a behavior test, and deliberately so: the
// property it protects is invisible to every other test here. The fakes inject a
// transport that rewrites requests to a local server, so a client built WITHOUT
// github.WithEnterpriseURLs still reaches the fake and the whole suite stays
// green. That is not hypothetical — it is how the defect described on
// TestNewGitHubClientBaseURL reached a pushed branch, and it was found by a
// rebase rather than by a test.
//
// TestNewGitHubClientBaseURL pins the helper's behavior; this pins that the
// helper is actually used. Only non-test files are checked, since the property
// is about the code paths that ship.
func TestGitHubClientHasOneConstructor(t *testing.T) {
	const constructor = "github.NewClient("

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir(.) = %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			strings.HasSuffix(name, "_test.go") || name == "client.go" {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s) = %v", name, err)
		}
		if bytes.Contains(b, []byte(constructor)) {
			t.Errorf("%s calls %s directly; use newGitHubClient instead, or a GitHub Enterprise Server deployment will silently send this request to api.github.com", name, constructor)
		}
	}

	// Guard the guard. If client.go stopped containing the call — renamed,
	// refactored, moved — the loop above would pass while asserting nothing, and
	// the invariant this test is named for would no longer exist.
	b, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatalf("ReadFile(client.go) = %v", err)
	}
	if !bytes.Contains(b, []byte(constructor)) {
		t.Errorf("client.go no longer calls %s, so this test has become vacuous", constructor)
	}
}
