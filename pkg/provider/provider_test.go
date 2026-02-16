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

	"github.com/coreos/go-oidc/v3/oidc"
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

func TestIsPermanentError_GoOIDCErrorPatterns(t *testing.T) {
	tests := []struct {
		statusCode int
		body       string
		permanent  bool
		name       string
	}{
		// Permanent errors - using actual HTTP status codes that will generate real go-oidc errors
		{400, `{"error":"invalid_request"}`, true, "400 Bad Request should be permanent"},
		{401, `{"error":"access_denied"}`, true, "401 Unauthorized should be permanent"},
		{403, `{"error":"insufficient_scope"}`, true, "403 Forbidden should be permanent"},
		{404, `{"error":"not_found"}`, true, "404 Not Found should be permanent"},
		{405, `{"error":"method_not_allowed"}`, true, "405 Method Not Allowed should be permanent"},
		{406, `{"error":"not_acceptable"}`, true, "406 Not Acceptable should be permanent"},
		{410, `{"error":"gone"}`, true, "410 Gone should be permanent"},
		{415, `{"error":"unsupported_media_type"}`, true, "415 Unsupported Media Type should be permanent"},
		{422, `{"error":"unprocessable_entity"}`, true, "422 Unprocessable Entity should be permanent"},
		{501, `{"error":"not_implemented"}`, true, "501 Not Implemented should be permanent"},

		// Temporary errors - should be retryable
		{429, `{"error":"rate_limited"}`, false, "429 Too Many Requests should be retryable"},
		{500, `{"error":"internal_server_error"}`, false, "500 Internal Server Error should be retryable"},
		{502, `{"error":"bad_gateway"}`, false, "502 Bad Gateway should be retryable"},
		{503, `{"error":"service_unavailable"}`, false, "503 Service Unavailable should be retryable"},
		{504, `{"error":"gateway_timeout"}`, false, "504 Gateway Timeout should be retryable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test server that returns the specific HTTP status code
			// This will generate actual go-oidc errors that we can test against
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.body))
			}))
			defer server.Close()

			// Use go-oidc to generate the actual error
			ctx := context.Background()
			_, err := oidc.NewProvider(ctx, server.URL)

			// go-oidc should return an error for non-200 responses
			if err == nil {
				t.Fatalf("Expected go-oidc to return an error for status %d, but got nil", tc.statusCode)
			}

			// Test our error classification function on the real go-oidc error
			result := isPermanentError(err)
			if result != tc.permanent {
				t.Errorf("isPermanentError() for real go-oidc error %q = %v, want %v", err.Error(), result, tc.permanent)
			}
		})
	}
}
