// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
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
	files, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "head", "r")
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
	_, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "head", "r")
	if err == nil || !strings.Contains(err.Error(), "changed during file listing") {
		t.Fatalf("error = %v", err)
	}
}

func TestPolicyFilesFromPRRejectsPersistentHeadMismatch(t *testing.T) {
	gets := 0
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v3/repos/o/r/pulls/7" {
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
			return
		}
		gets++
		json.NewEncoder(w).Encode(&github.PullRequest{
			Head: &github.PullRequestBranch{SHA: new("previous-head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(1),
		})
	}))
	_, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "event-head", "r")
	if !errors.Is(err, errPRHeadMismatch) || gets != 2 {
		t.Fatalf("error = %v, snapshot reads = %d, want head-mismatch sentinel after one retry", err, gets)
	}
}

func TestPolicyFilesFromPRRetriesLaggingHead(t *testing.T) {
	gets, lists := 0, 0
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/pulls/7":
			gets++
			head := "event-head"
			if gets == 1 {
				head = "previous-head"
			}
			json.NewEncoder(w).Encode(&github.PullRequest{
				Head: &github.PullRequestBranch{SHA: &head}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(1),
			})
		case "/api/v3/repos/o/r/pulls/7/files":
			lists++
			json.NewEncoder(w).Encode([]*github.CommitFile{{Filename: new(".github/chainguard/policy.sts.yaml"), Status: new("modified")}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	files, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "event-head", "r")
	if err != nil || len(files) != 1 || gets != 3 || lists != 1 {
		t.Fatalf("files=%v err=%v snapshot reads=%d lists=%d, want one policy after one retry", files, err, gets, lists)
	}
}

func TestPolicyFilesFromPRRetriesStaleFileCount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		counts [4]int
	}{
		{"file list lags stable count", [4]int{2, 2, 1, 1}},
		{"count changes during listing", [4]int{2, 1, 1, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gets, lists := 0, 0
			client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v3/repos/o/r/pulls/7":
					count := tc.counts[gets]
					gets++
					json.NewEncoder(w).Encode(&github.PullRequest{
						Head: &github.PullRequestBranch{SHA: new("head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: &count,
					})
				case "/api/v3/repos/o/r/pulls/7/files":
					lists++
					json.NewEncoder(w).Encode([]*github.CommitFile{{Filename: new(".github/chainguard/policy.sts.yaml"), Status: new("added")}})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			}))
			files, err := (&Validator{}).policyFilesFromPR(context.Background(), client, "o", "r", 7, "head", "r")
			if err != nil || len(files) != 1 || gets != 4 || lists != 2 {
				t.Fatalf("files=%v err=%v snapshot reads=%d lists=%d, want one policy after one retry", files, err, gets, lists)
			}
		})
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

func TestPolicyTreeSnapshotFileNamedGithubHasNoPolicies(t *testing.T) {
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/git/commits/head":
			json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("root")}})
		case "/api/v3/repos/o/r/git/trees/root":
			json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new(".github"), Type: new("blob"), SHA: new("blob")}}})
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	files, err := (&Validator{}).policyTreeSnapshot(context.Background(), client, "o", "r", "head")
	if err != nil || len(files) != 0 {
		t.Fatalf("files=%v err=%v, want no policies", files, err)
	}
}

func TestCompleteCompareChangesAtFileCap(t *testing.T) {
	for _, count := range []int{compareFileCap - 1, compareFileCap} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			treeReads := 0
			client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/git/") {
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
					return
				}
				if strings.Contains(r.URL.Path, "/git/trees/") {
					treeReads++
				}
				switch r.URL.Path {
				case "/api/v3/repos/o/r/git/commits/before", "/api/v3/repos/o/r/git/commits/after":
					ref := strings.TrimPrefix(r.URL.Path, "/api/v3/repos/o/r/git/commits/")
					json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new(ref + "-root")}})
				case "/api/v3/repos/o/r/git/trees/before-root", "/api/v3/repos/o/r/git/trees/after-root":
					ref := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v3/repos/o/r/git/trees/"), "-root")
					json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new(".github"), Type: new("tree"), SHA: new(ref + "-github")}}})
				case "/api/v3/repos/o/r/git/trees/before-github", "/api/v3/repos/o/r/git/trees/after-github":
					ref := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v3/repos/o/r/git/trees/"), "-github")
					json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new("chainguard"), Type: new("tree"), SHA: new(ref + "-policy")}}})
				case "/api/v3/repos/o/r/git/trees/before-policy":
					fmt.Fprint(w, `{"tree":[],"truncated":false}`)
				case "/api/v3/repos/o/r/git/trees/after-policy":
					json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new("snapshot.sts.yaml"), Type: new("blob"), SHA: new("blob")}}})
				default:
					t.Errorf("unexpected request %s", r.URL)
					http.NotFound(w, r)
				}
			}))
			files := make([]*github.CommitFile, count)
			for i := range files {
				files[i] = &github.CommitFile{Filename: new(fmt.Sprintf("other/%03d", i)), Status: new("modified")}
			}
			comparison := &github.CommitsComparison{Files: files}
			changes, method, err := (&Validator{}).completeCompareChanges(context.Background(), client, "o", "r", "before", "after", comparison)
			if err != nil {
				t.Fatal(err)
			}
			if count == compareFileCap-1 {
				if method != DetectionCompare || treeReads != 0 || len(changes) != 0 {
					t.Fatalf("method=%q treeReads=%d changes=%v, want compare, 0, none", method, treeReads, changes)
				}
			} else if method != DetectionSnapshot || treeReads != 6 || len(changes) != 1 || changes[0].Path != ".github/chainguard/snapshot.sts.yaml" {
				t.Fatalf("method=%q treeReads=%d changes=%v, want snapshot, 6, one policy", method, treeReads, changes)
			}
		})
	}
}

func TestCompleteCompareChangesMissingFilesUsesSnapshot(t *testing.T) {
	client := discoveryClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/repos/o/r/git/commits/after":
			json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("root")}})
		case "/api/v3/repos/o/r/git/trees/root":
			fmt.Fprint(w, `{"tree":[],"truncated":false}`)
		default:
			t.Errorf("unexpected request %s", r.URL)
			http.NotFound(w, r)
		}
	}))
	changes, method, err := (&Validator{}).completeCompareChanges(context.Background(), client, "o", "r", zeroHash, "after", &github.CommitsComparison{})
	if err != nil || method != DetectionSnapshot || len(changes) != 0 {
		t.Fatalf("changes=%v method=%q err=%v, want empty snapshot", changes, method, err)
	}
}

func TestCheckSuiteHeadMismatchAndRateLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		prStatus   int
		wantChecks int
	}{
		{"lagging PR head prevents partial green check", http.StatusOK, 0},
		{"PR rate limit prevents partial green check", http.StatusTooManyRequests, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks := 0
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/app/installations/1111/access_tokens":
					json.NewEncoder(w).Encode(map[string]any{"token": "test", "expires_at": "2099-01-01T00:00:00Z"})
				case "/api/v3/repos/foo/bar/compare/before...head":
					json.NewEncoder(w).Encode(&github.CommitsComparison{Files: []*github.CommitFile{{Filename: new(".github/chainguard/test.sts.yaml"), Status: new("modified")}}})
				case "/api/v3/repos/foo/bar/pulls/7":
					if tc.prStatus != http.StatusOK {
						w.WriteHeader(tc.prStatus)
						return
					}
					json.NewEncoder(w).Encode(&github.PullRequest{
						Head: &github.PullRequestBranch{SHA: new("previous-head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(1),
					})
				case "/api/v3/repos/foo/bar/contents/.github/chainguard/test.sts.yaml":
					json.NewEncoder(w).Encode(&github.RepositoryContent{Type: new("file"), Content: new("issuer: https://token.actions.githubusercontent.com\n")})
				case "/api/v3/repos/foo/bar/check-runs":
					checks++
					json.NewEncoder(w).Encode(&github.CheckRun{})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
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
			v := &Validator{Transport: transport}
			event := &github.CheckSuiteEvent{
				Installation: &github.Installation{ID: new(int64(1111))},
				Repo:         &github.Repository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), FullName: new("foo/bar"), DefaultBranch: new("main")},
				CheckSuite:   &github.CheckSuite{HeadSHA: new("head"), BeforeSHA: new("before"), HeadBranch: new("feature"), PullRequests: []*github.PullRequest{{Number: new(7)}}},
			}
			_, err = v.handleCheckSuite(context.Background(), event)
			if err != nil || checks != tc.wantChecks {
				t.Fatalf("handleCheckSuite err=%v checks=%d, want nil and %d checks", err, checks, tc.wantChecks)
			}
		})
	}
}

func TestPullRequestStaleHeadAcknowledged(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/1111/access_tokens":
			json.NewEncoder(w).Encode(map[string]any{"token": "test", "expires_at": "2099-01-01T00:00:00Z"})
		case "/api/v3/repos/foo/bar/pulls/7":
			json.NewEncoder(w).Encode(&github.PullRequest{
				Head: &github.PullRequestBranch{SHA: new("new-head")}, Base: &github.PullRequestBranch{SHA: new("base")}, ChangedFiles: new(1),
			})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
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
	v := &Validator{Transport: transport}
	event := &github.PullRequestEvent{
		Installation: &github.Installation{ID: new(int64(1111))},
		Repo:         &github.Repository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), FullName: new("foo/bar")},
		Action:       new("synchronize"), Number: new(7),
		PullRequest: &github.PullRequest{Head: &github.PullRequestBranch{SHA: new("old-head")}},
	}
	check, err := v.handlePullRequest(context.Background(), event)
	if check != nil || err != nil {
		t.Fatalf("handlePullRequest check=%v err=%v, want nil, nil", check, err)
	}
}

func TestPushDiscoveryRateLimitEmitsDegradedMarker(t *testing.T) {
	for _, atTreeFallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("tree-fallback=%t", atTreeFallback), func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/app/installations/1111/access_tokens":
					json.NewEncoder(w).Encode(map[string]any{"token": "test", "expires_at": "2099-01-01T00:00:00Z"})
				case "/api/v3/repos/foo/bar/compare/before...after":
					if !atTreeFallback {
						w.WriteHeader(http.StatusTooManyRequests)
						return
					}
					files := make([]*github.CommitFile, compareFileCap)
					for i := range files {
						files[i] = &github.CommitFile{Filename: new(fmt.Sprintf("other/%03d", i)), Status: new("modified")}
					}
					json.NewEncoder(w).Encode(&github.CommitsComparison{Files: files})
				case "/api/v3/repos/foo/bar/git/commits/after":
					w.WriteHeader(http.StatusTooManyRequests)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
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
			ce := &fakeCEClient{}
			emitter := newPolicyEmitter(ce, 1, 64)
			v := &Validator{Transport: transport, Emitter: emitter}
			commits := make([]*github.HeadCommit, 20)
			event := &github.PushEvent{
				Installation: &github.Installation{ID: new(int64(1111))},
				Repo:         &github.PushEventRepository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), FullName: new("foo/bar"), DefaultBranch: new("main")},
				Ref:          new("refs/heads/main"), Before: new("before"), After: new("after"), Commits: commits,
			}
			check, err := v.handlePush(context.Background(), event)
			if err != nil || check != nil {
				t.Fatalf("handlePush check=%v err=%v, want nil, nil", check, err)
			}
			events := drainEvents(t, emitter, ce)
			if len(events) != 1 {
				t.Fatalf("emitted %d events, want one degraded marker", len(events))
			}
			var marker PolicyEvent
			if err := json.Unmarshal(events[0].Data(), &marker); err != nil {
				t.Fatal(err)
			}
			if marker.Detection != DetectionDegraded || marker.Change != nil || marker.DetectionError == "" {
				t.Fatalf("marker = %+v, want degraded detection with error and no change", marker)
			}
		})
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
			ce := &fakeCEClient{}
			mux := http.NewServeMux()
			mux.HandleFunc("GET /api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
				t.Error("Compare must not be called with a zero before SHA")
				http.NotFound(w, r)
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/commits/deadbeef", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(&github.Commit{Tree: &github.Tree{SHA: new("tree")}})
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/trees/tree", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new(".github"), Type: new("tree"), SHA: new("github-tree")}}})
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/trees/github-tree", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: []*github.TreeEntry{{Path: new("chainguard"), Type: new("tree"), SHA: new("policy-tree")}}})
			})
			mux.HandleFunc("GET /api/v3/repos/foo/bar/git/trees/policy-tree", func(w http.ResponseWriter, r *http.Request) {
				if tc.status != http.StatusOK {
					w.WriteHeader(tc.status)
					return
				}
				if len(tc.entries) == 0 {
					fmt.Fprint(w, `{"sha":"tree","tree":[],"truncated":false}`)
					return
				}
				entries := make([]*github.TreeEntry, len(tc.entries))
				for i, entry := range tc.entries {
					name := strings.TrimPrefix(entry.GetPath(), policyDir+"/")
					entries[i] = &github.TreeEntry{Path: &name, Type: entry.Type, SHA: entry.SHA}
				}
				json.NewEncoder(w).Encode(&github.Tree{Truncated: new(false), Entries: entries})
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
			var emitter *PolicyEmitter
			if tc.name == "rate limited" {
				emitter = newPolicyEmitter(ce, 1, 64)
			}
			webhook := httptest.NewServer(&Validator{Transport: transport, WebhookSecret: [][]byte{secret}, Emitter: emitter})
			t.Cleanup(webhook.Close)
			commits := make([]*github.HeadCommit, 20)
			for i := range commits {
				commits[i] = &github.HeadCommit{Added: []string{"README.md"}}
			}
			body, err := json.Marshal(&github.PushEvent{
				Installation: &github.Installation{ID: new(int64(1111))},
				Repo:         &github.PushEventRepository{Owner: &github.User{Login: new("foo")}, Name: new("bar"), DefaultBranch: new("main")},
				Ref:          new("refs/heads/main"),
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
			if emitter != nil {
				events := drainEvents(t, emitter, ce)
				if len(events) != 1 {
					t.Fatalf("rate limit emitted %d events, want one degraded marker", len(events))
				}
				var marker PolicyEvent
				if err := json.Unmarshal(events[0].Data(), &marker); err != nil {
					t.Fatal(err)
				}
				if marker.Detection != DetectionDegraded || marker.Change != nil || marker.DetectionError == "" {
					t.Fatalf("rate limit marker = %+v, want degraded detection with error and no change", marker)
				}
			}
		})
	}
}
