// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v88/github"
	"github.com/octo-sts/app/pkg/octosts"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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

	gh, err := github.NewClient(
		github.WithHTTPClient(srv.Client()),
		github.WithEnterpriseURLs(srv.URL, srv.URL),
	)
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

func TestFilterValidatedFiles(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "mixed list keeps only the policy",
			input: []string{"README.md", ".github/chainguard/test.sts.yaml", ".github/chainguard/README.md", ".github/chainguard/config.yaml", "go.mod"},
			want:  []string{".github/chainguard/test.sts.yaml"},
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
		{
			name:  "order preserved",
			input: []string{".github/chainguard/test.sts.yaml", "README.md", ".github/chainguard/other.sts.yaml"},
			want:  []string{".github/chainguard/test.sts.yaml", ".github/chainguard/other.sts.yaml"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := filterValidatedFiles("some-service", tc.input)
			if !slices.Equal(tc.want, got) {
				t.Errorf("filterValidatedFiles(%v) = %v, want %v", tc.input, got, tc.want)
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
			got := v.filesFromPushEvent("some-service", event)
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

// TestCheckSuiteDefaultBranchSkipsNonPolicyFiles exercises the zeroHash /
// initial-commit branch of handleCheckSuite, which lists the policy directory
// instead of diffing it. The listing contains a README.md alongside the trust
// policy; only the policy may be fetched and validated.
func TestCheckSuiteDefaultBranchSkipsNonPolicyFiles(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}

	dirScanHit := false
	var fetchedMu sync.Mutex
	var fetched []string

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
		// A real policy directory can hold non-policy files too.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]*github.RepositoryContent{
			{
				Type: github.Ptr("file"),
				Name: github.Ptr("test.sts.yaml"),
				Path: github.Ptr(".github/chainguard/test.sts.yaml"),
			},
			{
				Type: github.Ptr("file"),
				Name: github.Ptr("README.md"),
				Path: github.Ptr(".github/chainguard/README.md"),
			},
		}); err != nil {
			t.Error(err)
		}
	})
	// Record every individual content fetch under the policy directory.
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard/", func(w http.ResponseWriter, r *http.Request) {
		fetchedMu.Lock()
		fetched = append(fetched, strings.TrimPrefix(r.URL.Path, "/api/v3/repos/foo/bar/contents/"))
		fetchedMu.Unlock()

		f, err := os.Open(filepath.Join("testdata", r.URL.Path))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		io.Copy(w, f)
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
		t.Fatal("directory scan API was not called but should have been for default branch initial commit")
	}

	fetchedMu.Lock()
	defer fetchedMu.Unlock()
	want := []string{".github/chainguard/test.sts.yaml"}
	if !slices.Equal(want, fetched) {
		t.Errorf("fetched content paths = %v, want %v", fetched, want)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Fatalf("expected success, got %s (summary: %s)", *got[0].Conclusion, got[0].Output.GetSummary())
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected %d so GitHub acks the delivery, got %d", http.StatusOK, resp.StatusCode)
	}
	if contentHits > 1 {
		t.Fatalf("expected at most 1 content fetch before aborting, got %d", contentHits)
	}
}

func TestIsGitHubRateLimited(t *testing.T) {
	resp := func(code int) *github.Response {
		return &github.Response{Response: &http.Response{StatusCode: code}}
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{{
		name: "typed rate limit error",
		err:  &github.RateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
		want: true,
	}, {
		name: "typed abuse rate limit error",
		err:  &github.AbuseRateLimitError{Response: &http.Response{StatusCode: http.StatusForbidden}},
		want: true,
	}, {
		name: "bare ErrorResponse 403",
		err:  &github.ErrorResponse{Response: resp(http.StatusForbidden).Response},
		want: true,
	}, {
		name: "bare ErrorResponse 429",
		err:  &github.ErrorResponse{Response: resp(http.StatusTooManyRequests).Response},
		want: true,
	}, {
		name: "ErrorResponse 404 is not a rate limit",
		err:  &github.ErrorResponse{Response: resp(http.StatusNotFound).Response},
		want: false,
	}, {
		name: "nil error",
		err:  nil,
		want: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := octosts.IsGitHubRateLimited(tc.err); got != tc.want {
				t.Errorf("IsGitHubRateLimited() = %v, want %v", got, tc.want)
			}
		})
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

func TestIsValidatedPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		repo string
		path string
		want bool
	}{
		{name: "trust policy in any repo", repo: "some-service", path: ".github/chainguard/foo.sts.yaml", want: true},
		{name: "trust policy in .github", repo: ".github", path: ".github/chainguard/foo.sts.yaml", want: true},
		{name: "allowlist in .github", repo: ".github", path: ".github/chainguard/trusted-token-issuers.yaml", want: true},
		// GitHub repository names are case-insensitive, and the read path
		// resolves .github through the API, so the predicate must fold.
		{name: "allowlist in .GitHub", repo: ".GitHub", path: ".github/chainguard/trusted-token-issuers.yaml", want: true},
		// A stray copy in an ordinary repo must NOT be validated, or it would be
		// parsed as a TrustPolicy and fail the check run.
		{name: "allowlist outside .github", repo: "some-service", path: ".github/chainguard/trusted-token-issuers.yaml", want: false},
		{name: "unrelated yaml", repo: "some-service", path: ".github/workflows/ci.yaml", want: false},
		{name: "nested deeper", repo: "some-service", path: ".github/chainguard/sub/foo.sts.yaml", want: false},
		{name: "readme", repo: ".github", path: "README.md", want: false},
		// Both of these live in the policy directory of the .github repository —
		// the one place BOTH arms of the predicate are live. They pin that the
		// allowlist arm matches one exact path rather than widening the trust
		// policy glob: neither carries the ".sts." infix, and neither is the
		// allowlist, so both must be rejected or they would be fetched and
		// parsed as TrustPolicies and fail the check run.
		{name: "readme inside the policy directory of .github", repo: ".github", path: ".github/chainguard/README.md", want: false},
		{name: "non-policy yaml inside the policy directory of .github", repo: ".github", path: ".github/chainguard/config.yaml", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidatedPath(tc.repo, tc.path); got != tc.want {
				t.Errorf("isValidatedPath(%q, %q) = %v, want %v", tc.repo, tc.path, got, tc.want)
			}
		})
	}
}

// TestDirScanBranchFiltersPaths covers handleCheckSuite's zeroHash branch, which
// lists the policy directory instead of diffing it. It previously appended every
// entry unfiltered, which would parse the organization allowlist — and anything
// else in the directory — as a TrustPolicy.
func TestDirScanBranchFiltersPaths(t *testing.T) {
	all := []string{
		".github/chainguard/foo.sts.yaml",
		".github/chainguard/trusted-token-issuers.yaml",
		".github/chainguard/README.md",
	}

	got := filterValidatedFiles("some-service", all)
	want := []string{".github/chainguard/foo.sts.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("filterValidatedFiles(some-service) = %v, want %v — the allowlist must not be validated outside .github", got, want)
	}

	got = filterValidatedFiles(".github", all)
	want = []string{".github/chainguard/foo.sts.yaml", ".github/chainguard/trusted-token-issuers.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("filterValidatedFiles(.github) = %v, want %v", got, want)
	}
}

// TestCheckSuiteDirScanSkipsNonPolicyFiles pins the PRODUCTION call site of the
// zeroHash directory-listing branch, which TestDirScanBranchFiltersPaths does not
// reach. The listing contains a README and the organization allowlist alongside a
// trust policy; in an ordinary repository only the trust policy may be fetched and
// parsed. Before filtering, the README and the allowlist were both fetched (404 in
// this fixture) and the check run concluded "failure".
func TestCheckSuiteDirScanSkipsNonPolicyFiles(t *testing.T) {
	got := []*github.CreateCheckRunOptions{}
	var fetched []string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	// The directory listing carries entries that are NOT trust policies.
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]*github.RepositoryContent{
			{Type: github.Ptr("file"), Name: github.Ptr("test.sts.yaml"), Path: github.Ptr(".github/chainguard/test.sts.yaml")},
			{Type: github.Ptr("file"), Name: github.Ptr("trusted-token-issuers.yaml"), Path: github.Ptr(".github/chainguard/trusted-token-issuers.yaml")},
			{Type: github.Ptr("file"), Name: github.Ptr("README.md"), Path: github.Ptr(".github/chainguard/README.md")},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/repos/foo/bar/contents/") {
			fetched = append(fetched, strings.TrimPrefix(r.URL.Path, "/api/v3/repos/foo/bar/contents/"))
		}
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
	v := &Validator{Transport: tr, WebhookSecret: [][]byte{secret}}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.Repository{
			Owner:         &github.User{Login: github.Ptr("foo")},
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

	wantFetched := []string{".github/chainguard/test.sts.yaml"}
	if !slices.Equal(fetched, wantFetched) {
		t.Errorf("directory scan fetched %v, want %v — non-policy entries must not be validated", fetched, wantFetched)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Errorf("expected success, got %s: %s", *got[0].Conclusion, got[0].Output.GetSummary())
	}
}

// TestValidateAllowlistContent checks that the webhook's validator runs the same
// parse AND compile the exchange path runs, so a check-run verdict cannot
// disagree with what happens at exchange time.
func TestValidateAllowlistContent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name: "valid",
			raw: `
issuers:
  - https://token.actions.githubusercontent.com
`,
		},
		{
			name: "valid audit with pattern",
			raw: `
mode: audit
issuer_patterns:
  - https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+
`,
		},
		// UnmarshalStrict alone would accept these; only Compile() catches them.
		{name: "uncompilable pattern", raw: "issuer_patterns:\n  - \"[unclosed\"\n", wantErr: true},
		{name: "uppercase host", raw: "issuers:\n  - https://Accounts.Google.com\n", wantErr: true},
		{name: "http non-loopback", raw: "issuers:\n  - http://evil.example.com\n", wantErr: true},
		{name: "empty lists", raw: "mode: enforce\n", wantErr: true},
		{name: "unknown mode", raw: "mode: off\nissuers:\n  - https://a.example.com\n", wantErr: true},
		// The singular spelling is the typo the plural field names invite.
		{name: "singular issuer_pattern", raw: "issuer_pattern:\n  - https://a\\.example\\.com\n", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := octosts.ParseOrgTrustedIssuers([]byte(tc.raw))
			if tc.wantErr && err == nil {
				t.Fatal("ParseOrgTrustedIssuers() = nil error, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ParseOrgTrustedIssuers() = %v, want nil", err)
			}
		})
	}
}

// runAllowlistCheckSuite drives the real check-run path over a fake GitHub for a
// check_suite on the default branch of org repository ".github", whose policy
// directory contains nothing but the trusted-issuer allowlist with the given
// contents. It returns the check runs created and the content paths fetched.
func runAllowlistCheckSuite(t *testing.T, allowlist string) ([]*github.CreateCheckRunOptions, []string) {
	t.Helper()

	got := []*github.CreateCheckRunOptions{}
	var fetched []string

	const allowlistPath = ".github/chainguard/trusted-token-issuers.yaml"

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/.github/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		got = append(got, opt)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/.github/contents/.github/chainguard", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode([]*github.RepositoryContent{
			{Type: github.Ptr("file"), Name: github.Ptr("trusted-token-issuers.yaml"), Path: github.Ptr(allowlistPath)},
		}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("GET /api/v3/repos/foo/.github/contents/"+allowlistPath, func(w http.ResponseWriter, _ *http.Request) {
		fetched = append(fetched, allowlistPath)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(&github.RepositoryContent{
			Type:     github.Ptr("file"),
			Name:     github.Ptr("trusted-token-issuers.yaml"),
			Path:     github.Ptr(allowlistPath),
			Encoding: github.Ptr("base64"),
			Content:  github.Ptr(base64.StdEncoding.EncodeToString([]byte(allowlist))),
		}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v3/repos/foo/.github/contents/") {
			fetched = append(fetched, strings.TrimPrefix(r.URL.Path, "/api/v3/repos/foo/.github/contents/"))
		}
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
	v := &Validator{Transport: tr, WebhookSecret: [][]byte{secret}}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.CheckSuiteEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.Repository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr(".github"),
			FullName:      github.Ptr("foo/.github"),
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
	return got, fetched
}

// TestCheckSuiteAllowlistValidConcludesSuccess pins the PRODUCTION dispatch in
// validatePolicies. A valid allowlist is NOT a valid TrustPolicy (nor a valid
// OrgTrustPolicy), so before the allowlist arm existed this concluded "failure"
// on a perfectly good file.
func TestCheckSuiteAllowlistValidConcludesSuccess(t *testing.T) {
	got, fetched := runAllowlistCheckSuite(t, `mode: audit
issuers:
  - https://token.actions.githubusercontent.com
issuer_patterns:
  - https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+
`)

	wantFetched := []string{".github/chainguard/trusted-token-issuers.yaml"}
	if !slices.Equal(fetched, wantFetched) {
		t.Errorf("fetched %v, want %v", fetched, wantFetched)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "success" {
		t.Errorf("expected success, got %s: %s", *got[0].Conclusion, got[0].Output.GetSummary())
	}
}

// TestCheckSuiteAllowlistInvalidConcludesFailure proves the dispatch COMPILES
// rather than merely unmarshalling. "[unclosed" is a well-formed YAML string, so
// yaml.UnmarshalStrict into OrgTrustedIssuers accepts it; only Compile() rejects
// it. A dispatch that only unmarshalled would pass the valid test above and fail
// this one.
func TestCheckSuiteAllowlistInvalidConcludesFailure(t *testing.T) {
	got, _ := runAllowlistCheckSuite(t, "issuer_patterns:\n  - \"[unclosed\"\n")

	if len(got) != 1 {
		t.Fatalf("expected 1 check run, got %d", len(got))
	}
	if *got[0].Conclusion != "failure" {
		t.Errorf("expected failure, got %s: %s", *got[0].Conclusion, got[0].Output.GetSummary())
	}
	if !strings.Contains(got[0].Output.GetSummary(), "invalid issuer_pattern") {
		t.Errorf("summary %q does not mention the uncompilable pattern — the file may have been merely unmarshalled", got[0].Output.GetSummary())
	}
}

// redirectTransport sends a request to a test server while leaving the original
// request's URL untouched, so wrappers above it still observe the real GitHub
// host. Rewriting the URL in place would hide the request from httpmetrics,
// which gates its GitHub rate-limit instrumentation on r.URL.Host both before
// and after the round trip.
type redirectTransport struct {
	inner  http.RoundTripper
	scheme string
	host   string
}

func (t *redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = t.scheme
	r2.URL.Host = t.host
	r2.Host = ""
	return t.inner.RoundTrip(r2)
}

// gaugeValueForLabels returns the value of the first sample of the named gauge
// whose labels are a superset of want.
func gaugeValueForLabels(t *testing.T, name string, want map[string]string) (float64, bool) {
	t.Helper()

	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			matched := true
			for k, v := range want {
				if !slices.ContainsFunc(m.GetLabel(), func(lp *dto.LabelPair) bool {
					return lp.GetName() == k && lp.GetValue() == v
				}) {
					matched = false
					break
				}
			}
			if matched {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestWebhookEnrichesMetricsContext is a regression test for GitHub rate-limit
// metrics being reported with an empty app_id label. httpmetrics reads the app
// and installation IDs off the request context, so a handler that never calls
// ghtransport.EnrichContext produces unattributable time series.
func TestWebhookEnrichesMetricsContext(t *testing.T) {
	// The metric vectors are process-global, so use IDs no other test uses to
	// keep the gathered series unambiguously ours.
	const (
		appID          = int64(424242)
		installationID = int64(999999)
		remaining      = 4999
	)

	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("POST /app/installations/%d/access_tokens", installationID), func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"token":"t","expires_at":%q}`, time.Now().Add(time.Hour).Format(time.RFC3339))
	})
	mux.HandleFunc("POST /repos/foo/bar/check-runs", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "{}")
	})
	// The client is pointed at api.github.com, whose host suppresses
	// go-github's /api/v3/ prefix, so re-add it when reaching for fixtures.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filepath.Join("testdata", "api", "v3", r.URL.Path))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Resource", "core")
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Limit", "5000")
		mux.ServeHTTP(w, r)
	}))
	defer gh.Close()

	ghURL, err := url.Parse(gh.URL)
	if err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Mirror the production transport chain from ghtransport.New: the
	// httpmetrics wrapper sits above the base transport, and only records
	// GitHub rate limits for requests whose host is api.github.com. Keeping
	// that host (and redirecting underneath the wrapper) is what makes the
	// app_id label observable here.
	base := metrics.WrapTransport(&redirectTransport{
		inner:  gh.Client().Transport,
		scheme: ghURL.Scheme,
		host:   ghURL.Host,
	})
	tr := ghinstallation.NewAppsTransportFromPrivateKey(base, appID, key)
	tr.BaseURL = "https://api.github.com"

	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(installationID)},
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200 OK, got\n%s", string(out))
	}

	got, ok := gaugeValueForLabels(t, "github_rate_limit_remaining", map[string]string{
		"app_id":          strconv.FormatInt(appID, 10),
		"installation_id": strconv.FormatInt(installationID, 10),
	})
	if !ok {
		t.Fatalf("no github_rate_limit_remaining series labelled app_id=%d installation_id=%d: "+
			"the webhook did not enrich the request context", appID, installationID)
	}
	if got != remaining {
		t.Errorf("github_rate_limit_remaining = %v, want %v", got, float64(remaining))
	}

	// The bug's signature: requests attributed to no app at all.
	if _, ok := gaugeValueForLabels(t, "github_rate_limit_remaining", map[string]string{
		"app_id":       "",
		"organization": "foo",
	}); ok {
		t.Error("found a github_rate_limit_remaining series with an empty app_id label")
	}
}
