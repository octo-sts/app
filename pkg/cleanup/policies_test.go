// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
)

const policyDir = ".github/chainguard"

// fakeGitHub serves an installation that can see:
//   - acme/svc: two policies plus files that are not policies;
//   - acme/.github: the cleanup policy, with no commit history;
//   - acme/fork: a fork with one policy;
//   - acme/empty: no policy directory;
//   - acme/old: archived, with a policy that must not be read;
//   - other/svc: a repository of a different owner.
//
// Repositories come back over two pages. Any request not listed fails the test.
func fakeGitHub(t *testing.T, override map[string]http.HandlerFunc) *github.Client {
	t.Helper()
	changed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	repo := func(owner, name string, archived, fork bool) string {
		return fmt.Sprintf(`{"name":%q,"owner":{"login":%q},"archived":%t,"fork":%t}`, name, owner, archived, fork)
	}
	file := func(name, typ string) string { return fmt.Sprintf(`{"name":%q,"type":%q}`, name, typ) }
	commit := fmt.Sprintf(`[{"commit":{"committer":{"date":%q}}}]`, changed.Format(time.RFC3339))

	routes := map[string]http.HandlerFunc{
		"/api/v3/installation/repositories": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprintf(w, `{"total_count":5,"repositories":[%s,%s]}`, repo("acme", ".github", false, false), repo("acme", "empty", false, false))
				return
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s?page=2>; rel="next"`, r.URL.Path))
			fmt.Fprintf(w, `{"total_count":5,"repositories":[%s,%s,%s,%s]}`,
				repo("acme", "svc", false, false), repo("acme", "old", true, false),
				repo("other", "svc", false, false), repo("acme", "fork", false, true))
		},
		"/api/v3/repos/acme/svc/contents/" + policyDir: func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "[%s]", strings.Join([]string{
				file("deploy.sts.yaml", "file"),
				file("release.sts.yaml", "file"),
				file("README.md", "file"),
				file("nested.sts.yaml", "dir"),
				file(".sts.yaml", "file"),
			}, ","))
		},
		"/api/v3/repos/acme/.github/contents/" + policyDir: func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "[%s]", file("octo-sts-cleanup.sts.yaml", "file"))
		},
		"/api/v3/repos/acme/fork/contents/" + policyDir: func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprintf(w, "[%s]", file("upstream.sts.yaml", "file"))
		},
		"/api/v3/repos/acme/empty/contents/" + policyDir: func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
		},
		"/api/v3/repos/acme/svc/commits": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("per_page") != "1" {
				t.Errorf("commits per_page = %q, want 1", r.URL.Query().Get("per_page"))
			}
			switch r.URL.Query().Get("path") {
			case policyDir + "/deploy.sts.yaml", policyDir + "/release.sts.yaml":
				fmt.Fprint(w, commit)
			default:
				t.Errorf("unexpected commits path %q", r.URL.Query().Get("path"))
			}
		},
		"/api/v3/repos/acme/.github/commits": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, "[]")
		},
		"/api/v3/repos/acme/fork/commits": func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, commit)
		},
	}
	for k, v := range override {
		routes[k] = v
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, ok := routes[r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		h(w, r)
	}))
	t.Cleanup(srv.Close)

	client, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestListPolicies(t *testing.T) {
	got, err := ListPolicies(t.Context(), fakeGitHub(t, nil), "acme", policyDir)
	if err != nil {
		t.Fatalf("ListPolicies() = %v", err)
	}
	changed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	want := []Policy{
		{Repo: "svc", Identity: "deploy", LastChanged: changed},
		{Repo: "svc", Identity: "release", LastChanged: changed},
		{Repo: "fork", Identity: "upstream", LastChanged: changed},
		{Repo: ".github", Identity: "octo-sts-cleanup"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ListPolicies() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestListPoliciesErrors(t *testing.T) {
	fail := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
	}
	tests := []struct {
		name    string
		route   string
		wantErr string
	}{{
		name:    "repository listing fails",
		route:   "/api/v3/installation/repositories",
		wantErr: "listing repositories",
	}, {
		name:    "policy directory read fails",
		route:   "/api/v3/repos/acme/svc/contents/" + policyDir,
		wantErr: "listing .github/chainguard in acme/svc",
	}, {
		name:    "commit lookup fails",
		route:   "/api/v3/repos/acme/svc/commits",
		wantErr: "last change of deploy.sts.yaml in acme/svc",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ListPolicies(t.Context(), fakeGitHub(t, map[string]http.HandlerFunc{tt.route: fail}), "acme", policyDir)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ListPolicies() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}
