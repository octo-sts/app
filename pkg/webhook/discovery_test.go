// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
)

func discoveryClient(t *testing.T, handler http.Handler) *github.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPolicyFilesFromPRPaginatesAndChecksSnapshot(t *testing.T) {
	gets := 0
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/pulls/7":
			gets++
			json.NewEncoder(w).Encode(&github.PullRequest{
				Head: &github.PullRequestBranch{SHA: new("head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(101),
			})
		case "/api/v3/repos/o/r/pulls/7/files":
			if r.URL.Query().Get("per_page") != "100" {
				t.Errorf("per_page = %q", r.URL.Query().Get("per_page"))
			}
			if r.URL.Query().Get("page") == "1" {
				files := make([]*github.CommitFile, 100)
				for i := range files {
					files[i] = &github.CommitFile{Filename: new(fmt.Sprintf("other/%03d", i)), Status: new("modified")}
				}
				w.Header().Set("Link", fmt.Sprintf("<http://%s%s?page=2&per_page=100>; rel=\"next\"", r.Host, r.URL.Path))
				json.NewEncoder(w).Encode(files)
			} else {
				json.NewEncoder(w).Encode([]*github.CommitFile{{Filename: new(".github/chainguard/policy.sts.yaml"), Status: new("added")}})
			}
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	files, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "head")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != ".github/chainguard/policy.sts.yaml" {
		t.Fatalf("files = %v", files)
	}
	if gets != 2 {
		t.Fatalf("snapshot reads = %d, want 2", gets)
	}
}

func TestPolicyFilesFromPRRejectsChangingSnapshot(t *testing.T) {
	gets := 0
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/pulls/7":
			gets++
			base := "base"
			if gets == 2 {
				base = "new-base"
			}
			json.NewEncoder(w).Encode(&github.PullRequest{
				Head: &github.PullRequestBranch{SHA: new("head")}, Base: &github.PullRequestBranch{SHA: &base}, ChangedFiles: new(1),
			})
		case "/api/v3/repos/o/r/pulls/7/files":
			json.NewEncoder(w).Encode([]*github.CommitFile{{Filename: new(".github/chainguard/policy.sts.yaml"), Status: new("modified")}})
		default:
			http.NotFound(w, r)
		}
	}))
	_, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "head")
	if err == nil || !strings.Contains(err.Error(), "changed during file listing") {
		t.Fatalf("error = %v", err)
	}
}

func TestPolicyTreeSnapshotRejectsTruncatedTree(t *testing.T) {
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/git/commits/head":
			json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("tree")}})
		case "/api/v3/repos/o/r/git/trees/tree":
			json.NewEncoder(w).Encode(&github.Tree{Truncated: new(true), Entries: []*github.TreeEntry{}})
		default:
			http.NotFound(w, r)
		}
	}))
	_, err := (&Validator{}).policyTreeSnapshot(context.Background(), client, "o", "r", "head")
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error = %v", err)
	}
}

func TestNewRefPushAtPayloadLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     int
		entries    []*github.TreeEntry
		wantStatus int
		wantChecks int
	}{
		{"policy present", http.StatusOK, []*github.TreeEntry{{Path: new(".github/chainguard/test.sts.yaml"), Type: new("blob"), SHA: new("blob")}}, http.StatusOK, 1},
		{"no policies", http.StatusOK, []*github.TreeEntry{}, http.StatusOK, 0},
		{"tree error", http.StatusInternalServerError, nil, http.StatusInternalServerError, 0},
		{"rate limited", http.StatusTooManyRequests, nil, http.StatusOK, 0},
		{"permission denied", http.StatusForbidden, nil, http.StatusInternalServerError, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := 0
			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
				t.Error("Compare must not be called with a zero before SHA")
				http.NotFound(w, r)
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/commits/deadbeef", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("tree")}})
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/trees/tree", func(w http.ResponseWriter, r *http.Request) {
				if tc.status != http.StatusOK {
					w.WriteHeader(tc.status)
					return
				}
				if len(tc.entries) == 0 {
					fmt.Fprint(w, `{"sha":"tree","tree":[],"truncated":false}`)
					return
				}
				json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: tc.entries})
			})
			mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
				checks++
				json.NewEncoder(w).Encode(&github.CheckRun{})
			})
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/app/installations/1111/access_tokens" {
					json.NewEncoder(w).Encode(map[string]any{"token": "test", "expires_at": "2099-01-01T00:00:00Z"})
					return
				}
				if r.URL.Path == "/api/v3/repos/foo/bar/contents/.github/chainguard/test.sts.yaml" {
					json.NewEncoder(w).Encode(&github.RepositoryContent{Type: new("file"), Content: new("issuer: https://token.actions.githubusercontent.com\n")})
					return
				}
				http.NotFound(w, r)
			})
			gh := httptest.NewServer(mux)
			t.Cleanup(gh.Close)
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			transport := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
			transport.BaseURL = gh.URL
			secret := []byte("test-secret")
			webhook := httptest.NewServer(&Validator{Transport: transport, WebhookSecret: [][]byte{secret}})
			t.Cleanup(webhook.Close)
			commits := make([]*github.HeadCommit, 20)
			for i := range commits {
				commits[i] = &github.HeadCommit{Added: []string{"README.md"}}
			}
			body, err := json.Marshal(&github.PushEvent{
				Installation: &github.Installation{ID: new(int64(1111))},
				Repo:         &github.PushEventRepository{Owner: &github.User{Login: new("foo")}, Name: new("bar")},
				Before:       new(zeroHash), After: new("deadbeef"), Commits: commits,
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, webhook.URL, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(github.SHA256SignatureHeader, signature(secret, body))
			req.Header.Set(HeaderEvent, "push")
			req.Header.Set("Content-Type", "application/json")
			resp, err := webhook.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || checks != tc.wantChecks {
				t.Fatalf("status=%d checks=%d, want status=%d checks=%d", resp.StatusCode, checks, tc.wantStatus, tc.wantChecks)
			}
		})
	}
}
