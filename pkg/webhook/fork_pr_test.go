// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v88/github"
)

func TestCheckSuitePRHome(t *testing.T) {
	for _, tc := range []struct {
		url, wantOwner, wantRepo string
		cross                    bool
	}{
		{"https://api.github.com/repos/foo/.github", "foo", ".github", true},
		{"https://ghe.example.com/api/v3/repos/foo/renamed-fork", "foo", "renamed-fork", false},
	} {
		pr := &github.PullRequest{Number: new(7), Base: &github.PullRequestBranch{Repo: &github.Repository{URL: &tc.url}}}
		owner, repo, cross, err := checkSuitePRHome(pr, "foo", "renamed-fork")
		if err != nil || owner != tc.wantOwner || repo != tc.wantRepo || cross != tc.cross {
			t.Fatalf("checkSuitePRHome(%q) = %q/%q, cross=%v, err=%v", tc.url, owner, repo, cross, err)
		}
	}
	if _, _, _, err := checkSuitePRHome(&github.PullRequest{Number: new(7), Base: &github.PullRequestBranch{Repo: &github.Repository{URL: new("https://api.github.com/repos/foo/.github/extra")}}}, "foo", "renamed-fork"); err == nil {
		t.Fatal("expected malformed base repository URL to fail")
	}
}

func TestForkCheckSuiteUsesBasePRAndForkContent(t *testing.T) {
	for _, tc := range []struct {
		name, baseRepo string
		fileStatus     int
		wantStatus     int
		wantChecks     int
	}{
		{"allowlist in renamed fork", ".github", http.StatusOK, http.StatusOK, 1},
		{"inaccessible base 404", ".github", http.StatusNotFound, http.StatusOK, 0},
		{"inaccessible base 403", ".github", http.StatusForbidden, http.StatusOK, 0},
		{"same repository 403", "renamed-fork", http.StatusForbidden, http.StatusInternalServerError, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := 0
			contentReads := 0
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/app/installations/1111/access_tokens":
					json.NewEncoder(w).Encode(map[string]any{"token": "test", "expires_at": "2099-01-01T00:00:00Z"})
				case "/api/v3/repos/foo/renamed-fork/contents/.github/chainguard":
					json.NewEncoder(w).Encode([]*github.RepositoryContent{})
				case "/api/v3/repos/foo/renamed-fork/contents/.github/chainguard/trusted-token-issuers.yaml":
					contentReads++
					raw := "mode: audit\nissuers:\n  - https://token.actions.githubusercontent.com\n"
					json.NewEncoder(w).Encode(&github.RepositoryContent{Type: new("file"), Encoding: new("base64"), Content: new(base64.StdEncoding.EncodeToString([]byte(raw)))})
				case "/api/v3/repos/foo/" + tc.baseRepo + "/pulls/7":
					json.NewEncoder(w).Encode(&github.PullRequest{Head: &github.PullRequestBranch{SHA: new("deadbeef")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(1)})
				case "/api/v3/repos/foo/" + tc.baseRepo + "/pulls/7/files":
					if tc.fileStatus != http.StatusOK {
						w.WriteHeader(tc.fileStatus)
						return
					}
					json.NewEncoder(w).Encode([]*github.CommitFile{{Filename: new(".github/chainguard/trusted-token-issuers.yaml"), Status: new("added")}})
				case "/api/v3/repos/foo/renamed-fork/check-runs":
					if r.Method != http.MethodPost {
						t.Errorf("unexpected check-run method %s", r.Method)
					}
					checks++
					var options github.CreateCheckRunOptions
					if err := json.NewDecoder(r.Body).Decode(&options); err != nil {
						t.Error(err)
					}
					if options.GetConclusion() != "success" {
						t.Errorf("check conclusion = %q, want success: %s", options.GetConclusion(), options.Output.GetSummary())
					}
					json.NewEncoder(w).Encode(&github.CheckRun{})
				default:
					t.Errorf("unexpected API call %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
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
			body, err := json.Marshal(&github.CheckSuiteEvent{
				Installation: &github.Installation{ID: new(int64(1111))},
				Repo:         &github.Repository{Owner: &github.User{Login: new("foo")}, Name: new("renamed-fork"), DefaultBranch: new("main")},
				CheckSuite:   &github.CheckSuite{HeadSHA: new("deadbeef"), BeforeSHA: new(zeroHash), HeadBranch: new("feature"), PullRequests: []*github.PullRequest{{Number: new(7), Base: &github.PullRequestBranch{Repo: &github.Repository{URL: new("https://api.github.com/repos/foo/" + tc.baseRepo)}}}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, webhook.URL, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(github.SHA256SignatureHeader, signature(secret, body))
			req.Header.Set(HeaderEvent, "check_suite")
			req.Header.Set("Content-Type", "application/json")
			resp, err := webhook.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || checks != tc.wantChecks {
				t.Fatalf("status=%d checks=%d, want status=%d checks=%d", resp.StatusCode, checks, tc.wantStatus, tc.wantChecks)
			}
			if tc.wantChecks == 1 && contentReads != 1 {
				t.Fatalf("fork content reads = %d, want 1", contentReads)
			}
		})
	}
}
