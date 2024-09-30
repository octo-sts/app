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
	"testing"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v62/github"
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
					Login: github.String(tc.org),
				},
				Repo: &github.PushEventRepository{
					Owner: &github.User{
						Login: github.String(tc.org),
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
			ID: github.Int64(1111),
		},
		Organization: &github.Organization{
			Login: github.String("foo"),
		},
		Repo: &github.PushEventRepository{
			Owner: &github.User{
				Login: github.String("foo"),
			},
			Name: github.String("bar"),
		},
		Before: github.String("1234"),
		After:  github.String("5678"),
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
		ExternalID: github.String("5678"),
		Status:     github.String("completed"),
		Conclusion: github.String("success"),
		// Use time from the response to ignore it.
		StartedAt:   &github.Timestamp{Time: got[0].StartedAt.Time},
		CompletedAt: &github.Timestamp{Time: got[0].CompletedAt.Time},
		Output: &github.CheckRunOutput{
			Title:   github.String("Valid trust policy."),
			Summary: github.String(""),
		},
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected check run (-want +got):\n%s", diff)
	}
}
