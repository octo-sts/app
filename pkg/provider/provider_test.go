// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewProviderWithRetry_Success(t *testing.T) {
	// Create a test server that responds successfully
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		issuerURL := "http://" + r.Host
		w.Write([]byte(`{"issuer":"` + issuerURL + `","authorization_endpoint":"` + issuerURL + `/auth","token_endpoint":"` + issuerURL + `/token","jwks_uri":"` + issuerURL + `/jwks"}`))
	}))
	defer server.Close()

	ctx := context.Background()
	provider, err := newProviderWithRetry(ctx, server.URL)
	if err != nil {
		t.Fatalf("Expected success, got error: %v", err)
	}
	if provider == nil {
		t.Fatal("Expected provider, got nil")
	}
}

func TestNewProviderWithRetry_EventualSuccess(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attempts, 1)
		if attempt < 3 {
			// Fail the first 2 attempts
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Succeed on the 3rd attempt
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		issuerURL := "http://" + r.Host
		w.Write([]byte(`{"issuer":"` + issuerURL + `","authorization_endpoint":"` + issuerURL + `/auth","token_endpoint":"` + issuerURL + `/token","jwks_uri":"` + issuerURL + `/jwks"}`))
	}))
	defer server.Close()

	ctx := context.Background()
	start := time.Now()
	provider, err := newProviderWithRetry(ctx, server.URL)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Expected eventual success, got error: %v", err)
	}
	if provider == nil {
		t.Fatal("Expected provider, got nil")
	}
	// The test server fails twice then succeeds on the third attempt
	if atomic.LoadInt32(&attempts) != 3 {
		t.Fatalf("Expected 3 attempts, got %d", attempts)
	}
	// Should have taken at least 1 second due to backoff after first failure
	if duration < 1*time.Second {
		t.Fatalf("Expected retry backoff, but completed too quickly: %v", duration)
	}
}

func TestNewProviderWithRetry_AllAttemptsFail(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := newProviderWithRetry(ctx, server.URL)

	if err == nil {
		t.Fatal("Expected error after all retries failed")
	}
	if provider != nil {
		t.Fatal("Expected nil provider after all retries failed")
	}
	// With backoff library, we expect multiple attempts but don't need to check exact count
	if atomic.LoadInt32(&attempts) < 3 {
		t.Fatalf("Expected at least 3 attempts, got %d", attempts)
	}
}

func TestNewProviderWithRetry_ContextCancellation(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		// Always fail to trigger retries
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	provider, err := newProviderWithRetry(ctx, server.URL)
	duration := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected context deadline exceeded, got: %v", err)
	}
	if provider != nil {
		t.Fatal("Expected nil provider after context cancellation")
	}
	// Should have attempted at least once but been canceled before completing all retries
	totalAttempts := atomic.LoadInt32(&attempts)
	if totalAttempts == 0 {
		t.Fatal("Expected at least one attempt before context cancellation")
	}
	// With backoff library and timeout, we expect some attempts but not too many
	if totalAttempts > 10 {
		t.Fatalf("Expected reasonable number of attempts due to context cancellation, got %d", totalAttempts)
	}
	// Should have been canceled around the timeout duration
	if duration > 3*time.Second {
		t.Fatalf("Expected cancellation around 2s, but took %v", duration)
	}
}

func TestGet_CacheHit(t *testing.T) {
	// Clear the cache first
	providers.Purge()

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		issuerURL := "http://" + r.Host
		w.Write([]byte(`{"issuer":"` + issuerURL + `","authorization_endpoint":"` + issuerURL + `/auth","token_endpoint":"` + issuerURL + `/token","jwks_uri":"` + issuerURL + `/jwks"}`))
	}))
	defer server.Close()

	ctx := context.Background()

	// First call should hit the server
	provider1, err := Get(ctx, server.URL)
	if err != nil {
		t.Fatalf("First Get() failed: %v", err)
	}
	if provider1 == nil {
		t.Fatal("Expected provider, got nil")
	}

	// Second call should hit the cache
	provider2, err := Get(ctx, server.URL)
	if err != nil {
		t.Fatalf("Second Get() failed: %v", err)
	}
	if provider2 == nil {
		t.Fatal("Expected cached provider, got nil")
	}

	// Should be the same instance from cache
	if provider1 != provider2 {
		t.Fatal("Expected same provider instance from cache")
	}
}
