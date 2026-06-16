// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v84/github"
)

func TestValidatePolicy(t *testing.T) {
	// Use prefetched data.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			t.Logf("%s not found", path)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	gh, err := github.NewClient(srv.Client()).WithEnterpriseURLs(srv.URL, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := slogtest.Context(t)
	if err := validatePolicies(ctx, gh, "foo", "bar", "deadbeef", []string{".github/chainguard/test.sts.yaml"}); err != nil {
		t.Fatal(err)
	}
}

func TestOrgFilter(t *testing.T) {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "should not be called", http.StatusUnauthorized)
	}))
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	if err != nil {
		t.Fatal(err)
	}
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
		Organizations: []string{"foo"},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	for _, tc := range []struct {
		org  string
		code int
	}{
		// This fails because the organization is in the filter, so we try to resolve it but it's pointed at a no-op github backend.
		{"foo", http.StatusInternalServerError},
		// This passes because the organization is not in the filter, so the server will fast-return a 200.
		{"bar", http.StatusOK},
	} {
		t.Run(tc.org, func(t *testing.T) {
			body, err := json.Marshal(github.PushEvent{
				Organization: &github.Organization{
					Login: github.Ptr(tc.org),
				},
				Repo: &github.PushEventRepository{
					Owner: &github.User{
						Login: github.Ptr(tc.org),
					},
				},
				Commits: []*github.HeadCommit{{
					Added: []string{".github/chainguard/test.sts.yaml"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Hub-Signature", signature(secret, body))
			req.Header.Set("X-GitHub-Event", "push")
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.code {
				out, _ := httputil.DumpResponse(resp, true)
				t.Fatalf("expected %d, got\n%s", tc.code, string(out))
			}
		})
	}
}

func signature(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	b := mac.Sum(nil)

	return fmt.Sprintf("sha256=%s", hex.EncodeToString(b))
}

func TestWebhookOK(t *testing.T) {
	// CheckRuns will be collected here.
	got := []*github.CreateCheckRunOptions{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			clog.FromContext(r.Context()).Errorf("%s not found", path)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	if err != nil {
		t.Fatal(err)
	}
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Organization: &github.Organization{
			Login: github.Ptr("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name: github.Ptr("bar"),
		},
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Commits: []*github.HeadCommit{{
			Added: []string{".github/chainguard/test.sts.yaml"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected %d, got\n%s", 200, string(out))
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}

	want := []*github.CreateCheckRunOptions{{
		Name:       "Trust Policy Validation",
		HeadSHA:    "5678",
		ExternalID: github.Ptr("5678"),
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr("success"),
		// Use time from the response to ignore it.
		StartedAt:   &github.Timestamp{Time: got[0].StartedAt.Time},
		CompletedAt: &github.Timestamp{Time: got[0].CompletedAt.Time},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr("Valid trust policy."),
			Summary: github.Ptr(""),
		},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected check run (-want +got):\n%s", diff)
	}
}

func TestFilterSTSFiles(t *testing.T) {
	v := &Validator{}
	for _, tc := range []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "matches sts.yaml files",
			input: []string{".github/chainguard/test.sts.yaml", "README.md", ".github/chainguard/other.sts.yaml"},
			want:  []string{".github/chainguard/test.sts.yaml", ".github/chainguard/other.sts.yaml"},
		},
		{
			name:  "no matches",
			input: []string{"README.md", "go.mod"},
			want:  nil,
		},
		{
			name:  "empty input",
			input: nil,
			want:  nil,
		},
		{
			name:  "nested path not matched",
			input: []string{".github/chainguard/subdir/test.sts.yaml"},
			want:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := v.filterSTSFiles(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("filterSTSFiles() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWebhookDeletedSTS(t *testing.T) {
	// CheckRuns will be collected here.
	got := []*github.CreateCheckRunOptions{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			clog.FromContext(r.Context()).Errorf("%s not found", path)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	if err != nil {
		t.Fatal(err)
	}
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Organization: &github.Organization{
			Login: github.Ptr("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name: github.Ptr("bar"),
		},
		Before: github.Ptr("9876"),
		After:  github.Ptr("4321"),
		Commits: []*github.HeadCommit{{
			Added: []string{".github/chainguard/test2.sts.yaml"},
		}, {
			Removed: []string{".github/chainguard/removed-example.sts.yaml"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected %d, got\n%s", 200, string(out))
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}

	want := []*github.CreateCheckRunOptions{{
		Name:       "Trust Policy Validation",
		HeadSHA:    "4321",
		ExternalID: github.Ptr("4321"),
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr("success"),
		// Use time from the response to ignore it.
		StartedAt:   &github.Timestamp{Time: got[0].StartedAt.Time},
		CompletedAt: &github.Timestamp{Time: got[0].CompletedAt.Time},
		Output: &github.CheckRunOutput{
			Title:   github.Ptr("Valid trust policy."),
			Summary: github.Ptr(""),
		},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected check run (-want +got):\n%s", diff)
	}
}

func TestFilesFromPushEvent(t *testing.T) {
	v := &Validator{}
	for _, tc := range []struct {
		name    string
		commits []*github.HeadCommit
		want    []string
	}{
		{
			name: "single commit with added file",
			commits: []*github.HeadCommit{{
				Added: []string{".github/chainguard/test.sts.yaml"},
			}},
			want: []string{".github/chainguard/test.sts.yaml"},
		},
		{
			name: "modified file included",
			commits: []*github.HeadCommit{{
				Modified: []string{".github/chainguard/test.sts.yaml"},
			}},
			want: []string{".github/chainguard/test.sts.yaml"},
		},
		{
			name: "removed file excluded",
			commits: []*github.HeadCommit{{
				Removed: []string{".github/chainguard/test.sts.yaml"},
			}},
			want: nil,
		},
		{
			name: "multiple commits deduplicated downstream",
			commits: []*github.HeadCommit{
				{Added: []string{".github/chainguard/a.sts.yaml"}},
				{Modified: []string{".github/chainguard/a.sts.yaml"}},
			},
			want: []string{".github/chainguard/a.sts.yaml", ".github/chainguard/a.sts.yaml"},
		},
		{
			name: "non-sts files filtered out",
			commits: []*github.HeadCommit{{
				Added:    []string{"README.md", ".github/chainguard/test.sts.yaml"},
				Modified: []string{"go.mod"},
			}},
			want: []string{".github/chainguard/test.sts.yaml"},
		},
		{
			name:    "nil commits",
			commits: nil,
			want:    nil,
		},
		{
			name: "boundary 19 commits uses payload",
			commits: func() []*github.HeadCommit {
				commits := make([]*github.HeadCommit, 19)
				for i := range commits {
					commits[i] = &github.HeadCommit{Added: []string{"README.md"}}
				}
				commits[18] = &github.HeadCommit{Added: []string{".github/chainguard/test.sts.yaml"}}
				return commits
			}(),
			want: []string{".github/chainguard/test.sts.yaml"},
		},
		{
			name: "mixed commits with sts files scattered",
			commits: []*github.HeadCommit{
				{Added: []string{"README.md", "go.mod"}},
				{Added: []string{".github/chainguard/a.sts.yaml"}, Modified: []string{"main.go"}},
				{Modified: []string{".github/chainguard/b.sts.yaml"}, Removed: []string{".github/chainguard/c.sts.yaml"}},
			},
			want: []string{".github/chainguard/a.sts.yaml", ".github/chainguard/b.sts.yaml"},
		},
		{
			name: "no sts files in any commit",
			commits: []*github.HeadCommit{
				{Added: []string{"README.md"}},
				{Modified: []string{"go.mod", "main.go"}},
			},
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := &github.PushEvent{Commits: tc.commits}
			got := v.filesFromPushEvent(event)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("filesFromPushEvent() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWebhookPushTruncatedFallback(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			clog.FromContext(r.Context()).Errorf("%s not found", path)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	if err != nil {
		t.Fatal(err)
	}
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	// Build 20 commits with no STS files to trigger truncation fallback.
	commits := make([]*github.HeadCommit, 20)
	for i := range commits {
		commits[i] = &github.HeadCommit{
			Added: []string{"README.md"},
		}
	}

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Organization: &github.Organization{
			Login: github.Ptr("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name: github.Ptr("bar"),
		},
		Before:  github.Ptr("1234"),
		After:   github.Ptr("5678"),
		Commits: commits,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected %d, got\n%s", 200, string(out))
	}

	// The Compare testdata for 1234...5678 has test.sts.yaml,
	// so the fallback should find it and create a CheckRun.
	if len(got) != 1 {
		t.Fatalf("expected 1 check run from Compare fallback, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s", *got[0].Conclusion)
	}
}

func TestWebhookPushNoSTSFiles(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	compareHit := false
	mux.HandleFunc("/api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
		compareHit = true
		t.Error("Compare API should not be called for < 20 commits")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Organization: &github.Organization{
			Login: github.Ptr("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name: github.Ptr("bar"),
		},
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Commits: []*github.HeadCommit{
			{Added: []string{"README.md"}},
			{Modified: []string{"go.mod", "main.go"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 check runs for non-STS push, got %d", len(got))
	}
	if compareHit {
		t.Fatal("Compare API was called but should not have been for < 20 commits")
	}
}

func TestWebhookPushBoundary19Commits(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	compareHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
		compareHit = true
		t.Error("Compare API should not be called for exactly 19 commits")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	// 19 commits — last one has an STS file. Should use payload, not Compare API.
	commits := make([]*github.HeadCommit, 19)
	for i := range commits {
		commits[i] = &github.HeadCommit{Added: []string{"README.md"}}
	}
	commits[18] = &github.HeadCommit{Added: []string{".github/chainguard/test.sts.yaml"}}

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Organization: &github.Organization{
			Login: github.Ptr("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name: github.Ptr("bar"),
		},
		Before:  github.Ptr("1234"),
		After:   github.Ptr("5678"),
		Commits: commits,
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run from payload path, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s", *got[0].Conclusion)
	}
	if compareHit {
		t.Fatal("Compare API was called but should not have been for 19 commits")
	}
}

func TestCheckSuiteNewBranchNoPRsSkipped(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	apiCalled := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/contents/", func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		t.Error("Contents API should not be called for skipped new branch")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
		apiCalled = true
		t.Error("Compare API should not be called for skipped new branch")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Sender: &github.User{Login: github.Ptr("test-user")},
		Action: github.Ptr("requested"),
		CheckSuite: &github.CheckSuite{
			ID:           github.Ptr(int64(1)),
			HeadSHA:      github.Ptr("deadbeef"),
			HeadBranch:   github.Ptr("feature-x"),
			BeforeSHA:    github.Ptr(zeroHash),
			PullRequests: []*github.PullRequest{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_suite")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 check runs for skipped new branch, got %d", len(got))
	}
	if apiCalled {
		t.Fatal("GitHub API was called but should not have been for new non-default branch with no PRs")
	}
}

func TestCheckSuiteNewBranchWithPRsProcessed(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	prFilesHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/pulls/42/files", func(w http.ResponseWriter, r *http.Request) {
		prFilesHit = true
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	// The zeroHash path does GetContents for the directory listing even
	// when PRs are present, so we need to serve that response.
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return an empty directory — the PR files handler provides the STS file.
		json.NewEncoder(w).Encode([]*github.RepositoryContent{})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Sender: &github.User{Login: github.Ptr("test-user")},
		Action: github.Ptr("requested"),
		CheckSuite: &github.CheckSuite{
			ID:         github.Ptr(int64(1)),
			HeadSHA:    github.Ptr("deadbeef"),
			HeadBranch: github.Ptr("feature-x"),
			BeforeSHA:  github.Ptr(zeroHash),
			PullRequests: []*github.PullRequest{
				{Number: github.Ptr(42)},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_suite")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if !prFilesHit {
		t.Fatal("PR files API was not called but should have been for new branch with PRs")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s", *got[0].Conclusion)
	}
}

func TestCheckSuiteDefaultBranchProcessed(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	dirScanHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		dirScanHit = true
		// Return a directory listing with one STS file.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]*github.RepositoryContent{
			{
				Type: github.Ptr("file"),
				Name: github.Ptr("test.sts.yaml"),
				Path: github.Ptr(".github/chainguard/test.sts.yaml"),
			},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Sender: &github.User{Login: github.Ptr("test-user")},
		Action: github.Ptr("requested"),
		CheckSuite: &github.CheckSuite{
			ID:           github.Ptr(int64(1)),
			HeadSHA:      github.Ptr("deadbeef"),
			HeadBranch:   github.Ptr("main"),
			BeforeSHA:    github.Ptr(zeroHash),
			PullRequests: []*github.PullRequest{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_suite")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if !dirScanHit {
		t.Fatal("Directory scan API was not called but should have been for default branch initial commit")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s", *got[0].Conclusion)
	}
}

func TestCheckSuiteExistingBranchUsesCompare(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	compareHit := false
	dirScanHit := false
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/compare/", func(w http.ResponseWriter, r *http.Request) {
		compareHit = true
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			clog.FromContext(r.Context()).Errorf("%s not found", path)
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		dirScanHit = true
		t.Error("Directory scan should not be called for existing branch")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{
				Login: github.Ptr("foo"),
			},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Sender: &github.User{Login: github.Ptr("test-user")},
		Action: github.Ptr("requested"),
		CheckSuite: &github.CheckSuite{
			ID:           github.Ptr(int64(1)),
			HeadSHA:      github.Ptr("5678"),
			HeadBranch:   github.Ptr("feature-y"),
			BeforeSHA:    github.Ptr("abcd1234"),
			PullRequests: []*github.PullRequest{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_suite")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}
	if !compareHit {
		t.Fatal("Compare API was not called but should have been for existing branch")
	}
	if dirScanHit {
		t.Fatal("Directory scan was called but should not have been for existing branch")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s", *got[0].Conclusion)
	}
}

func TestWebhookCheckSuiteBotSkipped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GitHub API should not be called for bot check_suite events, got %s %s", r.Method, r.URL.Path)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Action: github.Ptr("requested"),
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{Login: github.Ptr("foo")},
			Name:  github.Ptr("bar"),
		},
		Sender: &github.User{
			Login: github.Ptr("octo-sts[bot]"),
		},
		CheckSuite: &github.CheckSuite{
			HeadSHA:   github.Ptr("abc123"),
			BeforeSHA: github.Ptr("def456"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_suite")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 202 Accepted for bot sender, got\n%s", string(out))
	}
}

func TestWebhookCheckRunBotSkipped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("GitHub API should not be called for bot check_run events, got %s %s", r.Method, r.URL.Path)
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckRunEvent{
		Action: github.Ptr("created"),
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.Repository{
			Owner: &github.User{Login: github.Ptr("foo")},
			Name:  github.Ptr("bar"),
		},
		Sender: &github.User{
			Login: github.Ptr("some-other-app[bot]"),
		},
		CheckRun: &github.CheckRun{
			CheckSuite: &github.CheckSuite{
				HeadSHA:   github.Ptr("abc123"),
				BeforeSHA: github.Ptr("def456"),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "check_run")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 202 Accepted for bot sender, got\n%s", string(out))
	}
}

func TestWebhookPushAbortOnRateLimit(t *testing.T) {
	contentHits := 0

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		t.Error("CheckRun should not be created when rate-limited")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/contents/", func(w http.ResponseWriter, r *http.Request) {
		contentHits++
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "API rate limit exceeded",
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{
			ID: github.Ptr(int64(1111)),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{Login: github.Ptr("foo")},
			Name:  github.Ptr("bar"),
		},
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Commits: []*github.HeadCommit{{
			Added: []string{
				".github/chainguard/a.sts.yaml",
				".github/chainguard/b.sts.yaml",
				".github/chainguard/c.sts.yaml",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Hub-Signature", signature(secret, body))
	req.Header.Set("X-GitHub-Event", "push")
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp
	if contentHits > 1 {
		t.Fatalf("expected at most 1 content fetch before aborting, got %d", contentHits)
	}
}

func TestWebhookPullRequestActionSkipped(t *testing.T) {
	// Actions that can't change the file diff must not reach the GitHub API.
	for _, action := range []string{"labeled", "edited", "assigned", "review_requested", "closed", "ready_for_review"} {
		t.Run(action, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("GitHub API should not be called for pull_request action %q, got %s %s", action, r.Method, r.URL.Path)
				http.Error(w, "should not be called", http.StatusInternalServerError)
			})
			gh := httptest.NewServer(mux)
			defer gh.Close()

			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
			tr.BaseURL = gh.URL

			secret := []byte("hunter2")
			v := &Validator{
				Transport:     tr,
				WebhookSecret: [][]byte{secret},
			}
			srv := httptest.NewServer(v)
			defer srv.Close()

			body, err := json.Marshal(github.PullRequestEvent{
				Action: github.Ptr(action),
				Number: github.Ptr(1),
				Installation: &github.Installation{
					ID: github.Ptr(int64(1111)),
				},
				Repo: &github.Repository{
					Owner: &github.User{Login: github.Ptr("foo")},
					Name:  github.Ptr("bar"),
				},
				PullRequest: &github.PullRequest{
					Head: &github.PullRequestBranch{SHA: github.Ptr("abc123")},
				},
				Sender: &github.User{Login: github.Ptr("someone")},
			})
			if err != nil {
				t.Fatal(err)
			}

			req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Hub-Signature", signature(secret, body))
			req.Header.Set("X-GitHub-Event", "pull_request")
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusOK {
				out, _ := httputil.DumpResponse(resp, true)
				t.Fatalf("expected 200 OK, got\n%s", string(out))
			}
		})
	}
}

// TestWebhookInstallationTokenCached checks that two events for one
// installation mint only a single token.
func TestWebhookInstallationTokenCached(t *testing.T) {
	var mints atomic.Int64

	mux := http.NewServeMux()
	// Count mints; return a token valid for an hour so the cached client reuses it.
	mux.HandleFunc("POST /app/installations/1111/access_tokens", func(w http.ResponseWriter, _ *http.Request) {
		mints.Add(1)
		fmt.Fprintf(w, `{"token":"t","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))
	})
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "{}")
	})
	// Serve the trust-policy content fixture for everything else.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filepath.Join("testdata", r.URL.Path))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	gh := httptest.NewServer(mux)
	defer gh.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner: &github.User{Login: github.Ptr("foo")},
			Name:  github.Ptr("bar"),
		},
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Commits: []*github.HeadCommit{{
			Added: []string{".github/chainguard/test.sts.yaml"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Deliver the same event twice; the second must reuse the cached client.
	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewBuffer(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Hub-Signature", signature(secret, body))
		req.Header.Set("X-GitHub-Event", "push")
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req.WithContext(slogtest.Context(t)))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			out, _ := httputil.DumpResponse(resp, true)
			t.Fatalf("delivery %d: expected 200 OK, got\n%s", i, string(out))
		}
	}

	if got := mints.Load(); got != 1 {
		t.Fatalf("expected exactly 1 token mint across 2 events, got %d", got)
	}
}
