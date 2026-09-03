// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
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
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/protocol"
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
	if _, err := validatePolicies(ctx, gh, "foo", "bar", "deadbeef", []string{".github/chainguard/test.sts.yaml"}, ".github"); err != nil {
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
			got := filterValidatedFiles("some-service", tc.input, ".github")
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

func TestPathsToValidateFromPushEvent(t *testing.T) {
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
			name: "multiple commits deduplicated",
			commits: []*github.HeadCommit{
				{Added: []string{".github/chainguard/a.sts.yaml"}},
				{Modified: []string{".github/chainguard/a.sts.yaml"}},
			},
			want: []string{".github/chainguard/a.sts.yaml"},
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
			// The headline behaviour change: previously the path was collected
			// from Added and never removed again, so it was sent for
			// validation, 404'd at the head SHA, and failed the check run for
			// a policy that no longer exists.
			name: "added then deleted across commits excluded",
			commits: []*github.HeadCommit{
				{Added: []string{".github/chainguard/ephemeral.sts.yaml"}},
				{Removed: []string{".github/chainguard/ephemeral.sts.yaml"}},
			},
			want: nil,
		},
		{
			name: "modified then deleted across commits excluded",
			commits: []*github.HeadCommit{
				{Modified: []string{".github/chainguard/doomed.sts.yaml"}},
				{Removed: []string{".github/chainguard/doomed.sts.yaml"}},
			},
			want: nil,
		},
		{
			// The inverse must still be validated: the policy exists at the
			// head SHA, so it is live and has to be read.
			name: "deleted then re-added across commits included",
			commits: []*github.HeadCommit{
				{Removed: []string{".github/chainguard/revived.sts.yaml"}},
				{Added: []string{".github/chainguard/revived.sts.yaml"}},
			},
			want: []string{".github/chainguard/revived.sts.yaml"},
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
			got := pathsToValidate(v.policyChangesFromPushEvent("some-service", event))
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("pathsToValidate() mismatch (-want +got):\n%s", diff)
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

// TestCheckSuiteNoPolicyDirSkipped exercises the zeroHash / initial-commit
// branch of handleCheckSuite when the repository has no .github/chainguard
// directory: the directory scan 404s, which must be treated as "no policies"
// (logged, no check run) rather than failing the delivery with a 500.
func TestCheckSuiteNoPolicyDirSkipped(t *testing.T) {
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
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message": "Not Found"}`, http.StatusNotFound)
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
	if len(got) != 0 {
		t.Fatalf("expected 0 check runs when policy directory is missing, got %d", len(got))
	}
}

// TestCheckSuiteNonNotFoundDirScanError verifies that a non-404 error from the
// policy-directory scan still fails the delivery (so it is redelivered) rather
// than being swallowed like a missing directory.
func TestCheckSuiteNonNotFoundDirScanError(t *testing.T) {
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
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/.github/chainguard", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message": "Internal Server Error"}`, http.StatusInternalServerError)
	})
	// Catch-all serves the installation token mint (and anything else) from
	// testdata so the request reaches the directory scan above.
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
	if resp.StatusCode == 200 {
		t.Fatal("expected non-200 for a non-404 directory scan error, got 200")
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 check runs on scan error, got %d", len(got))
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
			if got := isValidatedPath(tc.repo, tc.path, ".github"); got != tc.want {
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

	got := filterValidatedFiles("some-service", all, ".github")
	want := []string{".github/chainguard/foo.sts.yaml"}
	if !slices.Equal(got, want) {
		t.Errorf("filterValidatedFiles(some-service) = %v, want %v — the allowlist must not be validated outside .github", got, want)
	}

	got = filterValidatedFiles(".github", all, ".github")
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

// fakeCEClient records the events a handler publishes. A nil Send result is an
// ACK as far as the SDK is concerned, so delivery always "succeeds".
type fakeCEClient struct {
	mu     sync.Mutex
	events []cloudevents.Event
}

func (f *fakeCEClient) Send(_ context.Context, e cloudevents.Event) protocol.Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

func (f *fakeCEClient) Request(ctx context.Context, e cloudevents.Event) (*cloudevents.Event, protocol.Result) {
	return nil, f.Send(ctx, e)
}

func (f *fakeCEClient) StartReceiver(context.Context, interface{}) error { return nil }

func (f *fakeCEClient) sent() []cloudevents.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.events)
}

// drainEvents shuts the emitter down and returns everything that reached ce.
// Delivery is asynchronous, so assertions have to run against a settled queue;
// draining rather than sleeping also exercises the shutdown path.
func drainEvents(t *testing.T, p *PolicyEmitter, ce *fakeCEClient) []cloudevents.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("emitter did not drain: %v", err)
	}
	return ce.sent()
}

func TestPolicyChangesFromCompare(t *testing.T) {
	v := &Validator{}
	for _, tc := range []struct {
		name  string
		files []*github.CommitFile
		want  []PolicyChange
	}{{
		name: "added, modified and removed",
		files: []*github.CommitFile{
			{Filename: github.Ptr(".github/chainguard/a.sts.yaml"), Status: github.Ptr("added")},
			{Filename: github.Ptr(".github/chainguard/b.sts.yaml"), Status: github.Ptr("modified")},
			{Filename: github.Ptr(".github/chainguard/c.sts.yaml"), Status: github.Ptr("removed")},
		},
		want: []PolicyChange{
			{Path: ".github/chainguard/a.sts.yaml", Policy: "a", Action: PolicyCreated},
			{Path: ".github/chainguard/b.sts.yaml", Policy: "b", Action: PolicyUpdated},
			{Path: ".github/chainguard/c.sts.yaml", Policy: "c", Action: PolicyDeleted},
		},
	}, {
		name: "rename records both sides",
		files: []*github.CommitFile{{
			Filename:         github.Ptr(".github/chainguard/new.sts.yaml"),
			PreviousFilename: github.Ptr(".github/chainguard/old.sts.yaml"),
			Status:           github.Ptr("renamed"),
		}},
		want: []PolicyChange{
			{Path: ".github/chainguard/new.sts.yaml", Policy: "new", Action: PolicyCreated},
			{Path: ".github/chainguard/old.sts.yaml", Policy: "old", Action: PolicyDeleted},
		},
	}, {
		// GitHub includes unchanged entries in some compares; the file is
		// byte-identical across the range, so nothing happened to it.
		name: "unchanged files are not updates",
		files: []*github.CommitFile{
			{Filename: github.Ptr(".github/chainguard/steady.sts.yaml"), Status: github.Ptr("unchanged")},
		},
		want: nil,
	}, {
		name: "unrecognised status is reported rather than dropped",
		files: []*github.CommitFile{
			{Filename: github.Ptr(".github/chainguard/odd.sts.yaml"), Status: github.Ptr("something-new")},
		},
		want: []PolicyChange{{
			Path: ".github/chainguard/odd.sts.yaml", Policy: "odd", Action: PolicyUpdated,
		}},
	}, {
		name: "non-policy files ignored",
		files: []*github.CommitFile{
			{Filename: github.Ptr("README.md"), Status: github.Ptr("added")},
			{Filename: github.Ptr(".github/chainguard/README.md"), Status: github.Ptr("modified")},
		},
		want: nil,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := v.policyChangesFromCompare(slogtest.Context(t), "some-service", tc.files)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("policyChangesFromCompare() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPathsToValidateExcludesDeletions(t *testing.T) {
	changes := []PolicyChange{
		{Path: ".github/chainguard/a.sts.yaml", Action: PolicyCreated},
		{Path: ".github/chainguard/b.sts.yaml", Action: PolicyDeleted},
		{Path: ".github/chainguard/c.sts.yaml", Action: PolicyUpdated},
	}
	want := []string{".github/chainguard/a.sts.yaml", ".github/chainguard/c.sts.yaml"}
	if diff := cmp.Diff(want, pathsToValidate(changes)); diff != "" {
		t.Errorf("pathsToValidate() mismatch (-want +got):\n%s", diff)
	}
}

// TestValidatePoliciesPerFileVerdicts pins the property the audit trail depends
// on: one broken policy must not taint the verdict of the others in the push.
func TestValidatePoliciesPerFileVerdicts(t *testing.T) {
	gh := githubTestServer(t, nil)
	ctx := slogtest.Context(t)

	results, err := validatePolicies(ctx, gh, "foo", "bar", "deadbeef", []string{
		".github/chainguard/test.sts.yaml",
		".github/chainguard/missing.sts.yaml",
	}, ".github")
	if err == nil {
		t.Fatal("expected an aggregate error for the unreadable policy")
	}

	if verr, ok := results[".github/chainguard/test.sts.yaml"]; !ok || verr != nil {
		t.Errorf("valid policy: got (%v, present=%t), want (nil, present=true)", verr, ok)
	}
	if verr, ok := results[".github/chainguard/missing.sts.yaml"]; !ok || verr == nil {
		t.Errorf("unreadable policy: got (%v, present=%t), want (non-nil, present=true)", verr, ok)
	}
}

// githubTestServer serves the testdata tree as the GitHub API, routing check
// run creations to onCheckRun when non-nil.
func githubTestServer(t *testing.T, onCheckRun func(*github.CreateCheckRunOptions)) *github.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		opt := new(github.CreateCheckRunOptions)
		if err := json.NewDecoder(r.Body).Decode(opt); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if onCheckRun != nil {
			onCheckRun(opt)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := filepath.Join("testdata", r.URL.Path)
		f, err := os.Open(path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client, err := github.NewClient(github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// TestPushEmitsPolicyEvents covers the audit trail end to end: one event per
// policy, per-file verdicts, and an unknown (nil) verdict for a deletion, which
// is never read at the head SHA and so cannot be called valid.
func TestPushEmitsPolicyEvents(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filepath.Join("testdata", r.URL.Path))
		if err != nil {
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
	tr.BaseURL = gh.URL

	ce := &fakeCEClient{}
	emitter := newPolicyEmitter(ce, 1, 64)
	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
		Emitter:       emitter,
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	push := github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Ref:    github.Ptr("refs/heads/main"),
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Sender: &github.User{Login: github.Ptr("mallory"), ID: github.Ptr(int64(99))},
		Commits: []*github.HeadCommit{{
			Added:   []string{".github/chainguard/test.sts.yaml", ".github/chainguard/missing.sts.yaml"},
			Removed: []string{".github/chainguard/gone.sts.yaml"},
		}},
	}
	body, err := json.Marshal(push)
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
		t.Fatalf("expected 200, got\n%s", string(out))
	}

	events := drainEvents(t, emitter, ce)
	if len(events) != 3 {
		t.Fatalf("expected one event per policy change, got %d", len(events))
	}

	byPath := map[string]PolicyEvent{}
	seenIndex := map[int]bool{}
	for _, e := range events {
		if e.Type() != "dev.octo-sts.policy" {
			t.Errorf("unexpected event type %q", e.Type())
		}
		var pe PolicyEvent
		if err := json.Unmarshal(e.Data(), &pe); err != nil {
			t.Fatal(err)
		}
		if pe.Org != "foo" || pe.Repo != "bar" {
			t.Errorf("got org/repo %q/%q, want foo/bar", pe.Org, pe.Repo)
		}
		if pe.Actor != "mallory" {
			t.Errorf("got actor %q, want mallory", pe.Actor)
		}
		if want := "foo/bar/" + pe.Change.Policy; e.Subject() != want {
			t.Errorf("got subject %q, want %q", e.Subject(), want)
		}
		if pe.ChangeCount != 3 {
			t.Errorf("got ChangeCount %d, want 3", pe.ChangeCount)
		}
		if pe.Detection != DetectionCommits {
			t.Errorf("got detection %q, want %q", pe.Detection, DetectionCommits)
		}
		seenIndex[pe.ChangeIndex] = true
		byPath[pe.Change.Path] = pe
	}

	// Indices must cover 0..n-1 so a consumer can spot a dropped event.
	for i := range 3 {
		if !seenIndex[i] {
			t.Errorf("missing ChangeIndex %d", i)
		}
	}

	valid, ok := byPath[".github/chainguard/test.sts.yaml"]
	if !ok {
		t.Fatal("no event for the valid policy")
	}
	if valid.Change.Action != PolicyCreated {
		t.Errorf("got action %q, want created", valid.Change.Action)
	}
	if valid.Valid == nil || !*valid.Valid {
		t.Errorf("valid policy: got Valid=%v, want true", valid.Valid)
	}
	if valid.Error != "" {
		t.Errorf("valid policy carried another file's error: %q", valid.Error)
	}

	broken, ok := byPath[".github/chainguard/missing.sts.yaml"]
	if !ok {
		t.Fatal("no event for the unreadable policy")
	}
	if broken.Valid == nil || *broken.Valid {
		t.Errorf("unreadable policy: got Valid=%v, want false", broken.Valid)
	}
	if broken.Error == "" {
		t.Error("unreadable policy: expected an error to be recorded")
	}

	deleted, ok := byPath[".github/chainguard/gone.sts.yaml"]
	if !ok {
		t.Fatal("no event for the deleted policy")
	}
	if deleted.Change.Action != PolicyDeleted {
		t.Errorf("got action %q, want deleted", deleted.Change.Action)
	}
	if deleted.Valid != nil {
		t.Errorf("deletion: got Valid=%v, want nil (never validated)", deleted.Valid)
	}
}

// TestPushNonDefaultBranchEmitsNothing keeps the audit trail scoped to policies
// that are actually live.
func TestPushNonDefaultBranchEmitsNothing(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(filepath.Join("testdata", r.URL.Path))
		if err != nil {
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
	tr.BaseURL = gh.URL

	ce := &fakeCEClient{}
	emitter := newPolicyEmitter(ce, 1, 64)
	secret := []byte("hunter2")
	v := &Validator{
		Transport:     tr,
		WebhookSecret: [][]byte{secret},
		Emitter:       emitter,
	}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Ref:     github.Ptr("refs/heads/feature"),
		Before:  github.Ptr("1234"),
		After:   github.Ptr("5678"),
		Commits: []*github.HeadCommit{{Added: []string{".github/chainguard/test.sts.yaml"}}},
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
		t.Fatalf("expected 200, got\n%s", string(out))
	}

	if got := drainEvents(t, emitter, ce); len(got) != 0 {
		t.Fatalf("expected no events for a non-default branch, got %d", len(got))
	}
}

func TestPolicyName(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{".github/chainguard/foo.sts.yaml", "foo"},
		{".github/chainguard/foo.bar.sts.yaml", "foo.bar"},
		{octosts.OrgTrustedIssuersPath, OrgTrustedIssuersPolicyName},
		// A literal ".sts.yaml" matches the glob octo-sts validates but has no
		// stem to name it by, so the filename stands in.
		{".github/chainguard/.sts.yaml", ".sts.yaml"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := policyName(tc.path); got != tc.want {
				t.Errorf("policyName(%q) = %q, want %q", tc.path, got, tc.want)
			}
			// Every name must be non-empty, or the event subject ends up with a
			// dangling separator.
			if policyName(tc.path) == "" {
				t.Error("policy name must not be empty")
			}
		})
	}
}

// policyTreeServer serves the two calls policySnapshot makes — a commit lookup
// to prove the ref resolves, then a listing of the policy directory — from an
// in-memory view of each ref. A ref absent from trees resolves but has no
// policy directory; a ref listed in unresolvable 404s the commit lookup, which
// is how a rewound-away SHA behaves once GitHub has collected it.
func policyTreeServer(t *testing.T, trees map[string][]string, unresolvable ...string) *github.Client {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/foo/bar/commits/{ref}", func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(unresolvable, r.PathValue("ref")) {
			http.Error(w, `{"message":"No commit found for SHA"}`, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"sha":"`+r.PathValue("ref")+`"}`)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/{path...}", func(w http.ResponseWriter, r *http.Request) {
		paths, ok := trees[r.URL.Query().Get("ref")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		entries := make([]map[string]string, 0, len(paths))
		for _, p := range paths {
			// "path:sha" so a test can hold a path steady while its content moves.
			name, sha, _ := strings.Cut(p, ":")
			entries = append(entries, map[string]string{
				"type": "file", "path": name, "name": filepath.Base(name), "sha": sha,
			})
		}
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			t.Error(err)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := github.NewClient(github.WithEnterpriseURLs(srv.URL, srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPolicyChangesFromSnapshot(t *testing.T) {
	const (
		added   = ".github/chainguard/added.sts.yaml"
		kept    = ".github/chainguard/kept.sts.yaml"
		edited  = ".github/chainguard/edited.sts.yaml"
		removed = ".github/chainguard/removed.sts.yaml"
	)

	for _, tc := range []struct {
		name          string
		before, after []string
		beforeRef     string
		unresolvable  []string
		want          []PolicyChange
		wantErr       bool
	}{{
		name:      "restores a policy deleted before the rewind",
		beforeRef: "before",
		before:    []string{},
		after:     []string{added + ":sha1"},
		want:      []PolicyChange{{Path: added, Policy: "added", Action: PolicyCreated}},
	}, {
		name:      "content change at a steady path is an update",
		beforeRef: "before",
		before:    []string{edited + ":old"},
		after:     []string{edited + ":new"},
		want:      []PolicyChange{{Path: edited, Policy: "edited", Action: PolicyUpdated}},
	}, {
		name:      "identical blobs report nothing",
		beforeRef: "before",
		before:    []string{kept + ":same"},
		after:     []string{kept + ":same"},
		want:      nil,
	}, {
		name:      "policy gone at after is a deletion",
		beforeRef: "before",
		before:    []string{removed + ":sha1"},
		after:     []string{},
		want:      []PolicyChange{{Path: removed, Policy: "removed", Action: PolicyDeleted}},
	}, {
		name:      "a created ref has no prior state",
		beforeRef: zeroHash,
		after:     []string{added + ":sha1"},
		want:      []PolicyChange{{Path: added, Policy: "added", Action: PolicyCreated}},
	}, {
		// The whole point of resolving the ref first: without it a collected
		// SHA would 404 and read as "no policies", turning every live policy
		// into a spurious deletion.
		name:         "an unreachable before is an error, not an empty tree",
		beforeRef:    "before",
		after:        []string{kept + ":sha1"},
		unresolvable: []string{"before"},
		wantErr:      true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			trees := map[string][]string{"after": tc.after}
			if tc.before != nil {
				trees["before"] = tc.before
			}
			client := policyTreeServer(t, trees, tc.unresolvable...)

			v := &Validator{}
			got, err := v.policyChangesFromSnapshot(slogtest.Context(t), client, "foo", "bar", tc.beforeRef, "after")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got changes %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("unexpected changes (-want +got):\n%s", diff)
			}
		})
	}
}

// forcedPushServer stands up the GitHub endpoints a forced push to the default
// branch exercises: the token mint and policy file reads come from testdata,
// while the policy directory listing is driven per-ref by trees.
func forcedPushServer(t *testing.T, trees map[string][]string, unresolvable ...string) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/bar/commits/{ref}", func(w http.ResponseWriter, r *http.Request) {
		if slices.Contains(unresolvable, r.PathValue("ref")) {
			http.Error(w, `{"message":"No commit found for SHA"}`, http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"sha":"`+r.PathValue("ref")+`"}`)
	})
	mux.HandleFunc("GET /api/v3/repos/foo/bar/contents/"+policyDir, func(w http.ResponseWriter, r *http.Request) {
		paths, ok := trees[r.URL.Query().Get("ref")]
		if !ok {
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		entries := make([]map[string]string, 0, len(paths))
		for _, p := range paths {
			name, sha, _ := strings.Cut(p, ":")
			entries = append(entries, map[string]string{
				"type": "file", "path": name, "name": filepath.Base(name), "sha": sha,
			})
		}
		if err := json.NewEncoder(w).Encode(entries); err != nil {
			t.Error(err)
		}
	})
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

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// sendForcedPush posts a forced push of an empty commit list to the default
// branch — the shape a pure rewind (git reset --hard <ancestor>; push -f) has.
func sendForcedPush(t *testing.T, v *Validator, secret []byte) {
	t.Helper()

	srv := httptest.NewServer(v)
	t.Cleanup(srv.Close)

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Ref:     github.Ptr("refs/heads/main"),
		Before:  github.Ptr("before"),
		After:   github.Ptr("after"),
		Forced:  github.Ptr(true),
		Sender:  &github.User{Login: github.Ptr("mallory"), ID: github.Ptr(int64(99))},
		Commits: []*github.HeadCommit{},
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
		t.Fatalf("expected 200, got\n%s", string(out))
	}
}

func forcedPushValidator(t *testing.T, gh *httptest.Server, ce *fakeCEClient) (*Validator, []byte, *PolicyEmitter) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tr := ghinstallation.NewAppsTransportFromPrivateKey(gh.Client().Transport, 1234, key)
	tr.BaseURL = gh.URL

	emitter := newPolicyEmitter(ce, 1, 64)
	secret := []byte("hunter2")
	return &Validator{Transport: tr, WebhookSecret: [][]byte{secret}, Emitter: emitter}, secret, emitter
}

// TestForcedPushRewindEmitsRestoredPolicy covers the suppression primitive a
// commit-derived audit trail has: deleting a policy is recorded, then a rewind
// force-push makes it live again while carrying no commits at all. Detection
// has to compare state, not commits, or the stream's last word on the policy
// stays "deleted" while the policy is back in force.
func TestForcedPushRewindEmitsRestoredPolicy(t *testing.T) {
	const restored = ".github/chainguard/test.sts.yaml"

	gh := forcedPushServer(t, map[string][]string{
		"before": {},
		"after":  {restored + ":sha1"},
	})
	ce := &fakeCEClient{}
	v, secret, emitter := forcedPushValidator(t, gh, ce)
	sendForcedPush(t, v, secret)

	events := drainEvents(t, emitter, ce)
	if len(events) != 1 {
		t.Fatalf("expected the restored policy to be reported, got %d events", len(events))
	}

	var pe PolicyEvent
	if err := json.Unmarshal(events[0].Data(), &pe); err != nil {
		t.Fatal(err)
	}
	if pe.Change == nil {
		t.Fatal("expected a change to be attached")
	}
	if pe.Change.Path != restored || pe.Change.Action != PolicyCreated {
		t.Errorf("got %s %q, want %s created", pe.Change.Action, pe.Change.Path, restored)
	}
	if pe.Detection != DetectionSnapshot {
		t.Errorf("got detection %q, want %q", pe.Detection, DetectionSnapshot)
	}
	if !pe.Forced {
		t.Error("expected the event to record that the push was forced")
	}
	// The restored policy is live, so its verdict has to be authoritative
	// rather than the unknown a deletion would carry.
	if pe.Valid == nil || !*pe.Valid {
		t.Errorf("got Valid=%v, want true", pe.Valid)
	}
}

// TestForcedPushDegradedEmitsMarker covers the case where the pre-push SHA has
// been collected and the snapshot cannot be taken. Silence is what suppression
// looks like, so the gap has to be published rather than merely logged.
func TestForcedPushDegradedEmitsMarker(t *testing.T) {
	gh := forcedPushServer(t, map[string][]string{
		"after": {".github/chainguard/test.sts.yaml:sha1"},
	}, "before")
	ce := &fakeCEClient{}
	v, secret, emitter := forcedPushValidator(t, gh, ce)
	sendForcedPush(t, v, secret)

	events := drainEvents(t, emitter, ce)
	if len(events) != 1 {
		t.Fatalf("expected a detection marker, got %d events", len(events))
	}

	var pe PolicyEvent
	if err := json.Unmarshal(events[0].Data(), &pe); err != nil {
		t.Fatal(err)
	}
	if pe.Change != nil {
		t.Errorf("marker should carry no change, got %+v", pe.Change)
	}
	if pe.Detection != DetectionDegraded {
		t.Errorf("got detection %q, want %q", pe.Detection, DetectionDegraded)
	}
	if pe.DetectionError == "" {
		t.Error("expected the marker to explain why detection degraded")
	}
	// A marker with no policy attached still has to be attributable.
	if want := "foo/bar"; events[0].Subject() != want {
		t.Errorf("got subject %q, want %q", events[0].Subject(), want)
	}
	if pe.Actor != "mallory" {
		t.Errorf("got actor %q, want mallory", pe.Actor)
	}
}

// TestPushAddThenDeleteCreatesNoCheckRun pins the behaviour change that came
// with sharing one change list between reporting and validation.
//
// A policy added and then removed in the same push does not exist at the head
// SHA. Validating it would 404 and fail the check run for a file the push
// deliberately left absent, which is the same reasoning the old code already
// applied to removals within a single diff — it just never applied it across
// commits. The removal is still reported, because it is a real policy change.
func TestPushAddThenDeleteCreatesNoCheckRun(t *testing.T) {
	const ephemeral = ".github/chainguard/ephemeral.sts.yaml"

	var checkRuns atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, _ *http.Request) {
		checkRuns.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	// Deliberately unregistered: reading the policy at the head SHA would 404,
	// which is exactly the failure this test asserts we no longer provoke.
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

	ce := &fakeCEClient{}
	emitter := newPolicyEmitter(ce, 1, 64)
	secret := []byte("hunter2")
	v := &Validator{Transport: tr, WebhookSecret: [][]byte{secret}, Emitter: emitter}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Ref:    github.Ptr("refs/heads/main"),
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Sender: &github.User{Login: github.Ptr("octocat"), ID: github.Ptr(int64(1))},
		Commits: []*github.HeadCommit{
			{Added: []string{ephemeral}},
			{Removed: []string{ephemeral}},
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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := httputil.DumpResponse(resp, true)
		t.Fatalf("expected 200, got\n%s", string(out))
	}

	if got := checkRuns.Load(); got != 0 {
		t.Errorf("created %d check runs for a policy that does not exist at the head SHA, want 0", got)
	}

	// The deletion is still a policy change and still has to be reported.
	events := drainEvents(t, emitter, ce)
	if len(events) != 1 {
		t.Fatalf("expected the deletion to be reported, got %d events", len(events))
	}
	var pe PolicyEvent
	if err := json.Unmarshal(events[0].Data(), &pe); err != nil {
		t.Fatal(err)
	}
	if pe.Change == nil || pe.Change.Action != PolicyDeleted {
		t.Errorf("got %+v, want a deletion of %s", pe.Change, ephemeral)
	}
	if pe.Valid != nil {
		t.Errorf("got Valid=%v, want nil — the path was never read", pe.Valid)
	}
	if pe.PushError != "" {
		t.Errorf("nothing failed handling this push, got push_error %q", pe.PushError)
	}
}

// TestRateLimitedPushReportsNoVerdict covers the distinction PushError draws.
//
// A rate limit aborts validation partway, so the policies it never reached have
// no verdict. Reporting them as valid would be a fabricated pass and reporting
// them as invalid would be a fabricated failure, so they report neither: Valid
// is nil and PushError carries the reason the answer is missing.
func TestRateLimitedPushReportsNoVerdict(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v3/repos/foo/bar/check-runs", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("CheckRun should not be created when rate-limited")
		http.Error(w, "should not be called", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v3/repos/foo/bar/contents/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"message": "API rate limit exceeded"}) //nolint:errcheck // test server
	})
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

	ce := &fakeCEClient{}
	emitter := newPolicyEmitter(ce, 1, 64)
	secret := []byte("hunter2")
	v := &Validator{Transport: tr, WebhookSecret: [][]byte{secret}, Emitter: emitter}
	srv := httptest.NewServer(v)
	defer srv.Close()

	body, err := json.Marshal(github.PushEvent{
		Installation: &github.Installation{ID: github.Ptr(int64(1111))},
		Repo: &github.PushEventRepository{
			Owner:         &github.User{Login: github.Ptr("foo")},
			Name:          github.Ptr("bar"),
			FullName:      github.Ptr("foo/bar"),
			DefaultBranch: github.Ptr("main"),
		},
		Ref:    github.Ptr("refs/heads/main"),
		Before: github.Ptr("1234"),
		After:  github.Ptr("5678"),
		Sender: &github.User{Login: github.Ptr("octocat"), ID: github.Ptr(int64(1))},
		Commits: []*github.HeadCommit{{
			Added: []string{".github/chainguard/a.sts.yaml", ".github/chainguard/b.sts.yaml"},
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

	events := drainEvents(t, emitter, ce)
	if len(events) != 2 {
		t.Fatalf("expected both policy changes to be reported, got %d events", len(events))
	}
	for _, e := range events {
		var pe PolicyEvent
		if err := json.Unmarshal(e.Data(), &pe); err != nil {
			t.Fatal(err)
		}
		if pe.Valid != nil {
			t.Errorf("%s: got Valid=%v, want nil — the rate limit means there is no verdict", pe.Change.Path, *pe.Valid)
		}
		if pe.PushError == "" {
			t.Errorf("%s: want push_error explaining why the verdict is missing", pe.Change.Path)
		}
		// The change itself is still reported: it came from the signed
		// payload, which the rate limit does not affect.
		if pe.Change == nil || pe.Change.Action != PolicyCreated {
			t.Errorf("got %+v, want the creation to be reported regardless", pe.Change)
		}
	}
}
