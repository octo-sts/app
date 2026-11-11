// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
)

// checkRunServer answers PATCH /repos/o/r/check-runs/1 with statuses[i] on
// the i-th call, repeating the last status once they run out.
func checkRunServer(t *testing.T, statuses ...int) (*github.Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/repos/o/r/check-runs/1" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := int(calls.Add(1))
		code := statuses[min(n, len(statuses))-1]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(`{"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"message":"refused"}`))
	}))
	t.Cleanup(srv.Close)

	base := srv.URL + "/"
	ghc, err := github.NewClient(github.WithHTTPClient(srv.Client()), github.WithURLs(&base, &base))
	if err != nil {
		t.Fatal(err)
	}
	return ghc, &calls
}

func statusOf(err error) int {
	var ghErr *github.ErrorResponse
	if errors.As(err, &ghErr) && ghErr.Response != nil {
		return ghErr.Response.StatusCode
	}
	return 0
}

func TestUpdateCheckRunWithRetry(t *testing.T) {
	tests := []struct {
		name       string
		statuses   []int
		attempts   int
		wantCalls  int32
		wantStatus int // 0 means success
	}{{
		name:      "succeeds first try",
		statuses:  []int{http.StatusOK},
		attempts:  5,
		wantCalls: 1,
	}, {
		name:      "404 then recovers (GitHub lag)",
		statuses:  []int{http.StatusNotFound, http.StatusNotFound, http.StatusOK},
		attempts:  5,
		wantCalls: 3,
	}, {
		name:       "404 every time (different app)",
		statuses:   []int{http.StatusNotFound},
		attempts:   5,
		wantCalls:  5,
		wantStatus: http.StatusNotFound,
	}, {
		name:       "403 is not retried",
		statuses:   []int{http.StatusForbidden, http.StatusOK},
		attempts:   5,
		wantCalls:  1,
		wantStatus: http.StatusForbidden,
	}, {
		name:       "5xx is not retried",
		statuses:   []int{http.StatusBadGateway, http.StatusOK},
		attempts:   5,
		wantCalls:  1,
		wantStatus: http.StatusBadGateway,
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ghc, calls := checkRunServer(t, tc.statuses...)
			err := updateCheckRunWithRetry(context.Background(), ghc, "o", "r", 1, github.UpdateCheckRunOptions{Name: "x"}, tc.attempts, time.Millisecond)
			if got := statusOf(err); got != tc.wantStatus {
				t.Errorf("status = %d (err %v), want %d", got, err, tc.wantStatus)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("calls = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

func TestUpdateCheckRunWithRetryStopsOnCancel(t *testing.T) {
	ghc, calls := checkRunServer(t, http.StatusNotFound)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := updateCheckRunWithRetry(ctx, ghc, "o", "r", 1, github.UpdateCheckRunOptions{Name: "x"}, 5, time.Hour)
	if err == nil {
		t.Fatal("expected an error after cancel")
	}
	if got := calls.Load(); got > 1 {
		t.Errorf("calls = %d, want at most 1 after cancel", got)
	}
}
