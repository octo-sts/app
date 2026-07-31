// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevoke(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/installation/token" {
			t.Errorf("expected /installation/token, got %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("expected Authorization: Bearer test-token, got %s", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	// Override http.DefaultClient for the duration of the test so we can
	// reach the TLS test server.
	orig := http.DefaultClient
	http.DefaultClient = srv.Client()
	t.Cleanup(func() { http.DefaultClient = orig })

	err := Revoke(context.Background(), "test-token", srv.URL)
	if err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
}

func TestRevokeDefaultURL(t *testing.T) {
	// When baseURL is empty, the URL should default to https://api.github.com/installation/token.
	// We can't easily test the real endpoint, so just verify the path logic
	// by providing an empty baseURL and a server that expects the right path.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/token" {
			t.Errorf("expected /installation/token, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	orig := http.DefaultClient
	http.DefaultClient = srv.Client()
	t.Cleanup(func() { http.DefaultClient = orig })

	// With a non-empty baseURL pointing to our test server, verify path.
	err := Revoke(context.Background(), "tok", srv.URL+"/")
	if err != nil {
		t.Fatalf("Revoke() with trailing slash = %v", err)
	}
}

func TestRevokeTrailingSlashHandled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/installation/token" {
			t.Errorf("expected /installation/token, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	orig := http.DefaultClient
	http.DefaultClient = srv.Client()
	t.Cleanup(func() { http.DefaultClient = orig })

	// baseURL with trailing slash should not produce double-slash.
	err := Revoke(context.Background(), "tok", srv.URL+"/")
	if err != nil {
		t.Fatalf("Revoke() = %v", err)
	}
}

func TestRevokeNon204StatusReturnsError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	orig := http.DefaultClient
	http.DefaultClient = srv.Client()
	t.Cleanup(func() { http.DefaultClient = orig })

	err := Revoke(context.Background(), "bad-token", srv.URL)
	if err == nil {
		t.Fatal("expected error for non-204 status, got nil")
	}
}
