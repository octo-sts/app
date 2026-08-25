// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type stubLimiter struct {
	res Result
	err error
}

func (s stubLimiter) Allow(context.Context, string) (Result, error) {
	return s.res, s.err
}

// decisionCount reads the current value of the decisions counter so tests can
// assert on deltas. The counter is process-global, so absolute values depend
// on test ordering.
func decisionCount(t *testing.T, backend, decision string) float64 {
	t.Helper()
	return testutil.ToFloat64(mDecisions.WithLabelValues(backend, decision))
}

func TestObservedRecordsDecision(t *testing.T) {
	for _, tc := range []struct {
		name     string
		limiter  Limiter
		decision string
	}{{
		name:     "allowed",
		limiter:  stubLimiter{res: Result{Allowed: true}},
		decision: decisionAllowed,
	}, {
		name:     "denied",
		limiter:  stubLimiter{res: Result{Allowed: false}},
		decision: decisionDenied,
	}, {
		name:     "error",
		limiter:  stubLimiter{err: errors.New("store unreachable")},
		decision: decisionError,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			backend := "test-" + tc.name
			before := decisionCount(t, backend, tc.decision)

			if _, err := Observed(tc.limiter, backend).Allow(context.Background(), "caller"); err != nil && tc.decision != decisionError {
				t.Fatalf("unexpected error: %v", err)
			}

			if got := decisionCount(t, backend, tc.decision) - before; got != 1 {
				t.Errorf("decisions_total{backend=%q,decision=%q} rose by %v, want 1", backend, tc.decision, got)
			}
		})
	}
}

// An error must be counted as an error and not also as a denial, otherwise a
// broken backend would look like callers exceeding their budget.
func TestObservedDoesNotDoubleCountErrors(t *testing.T) {
	const backend = "test-no-double-count"
	beforeDenied := decisionCount(t, backend, decisionDenied)

	limiter := Observed(stubLimiter{err: errors.New("boom")}, backend)
	if _, err := limiter.Allow(context.Background(), "caller"); err == nil {
		t.Fatal("expected the underlying error to be propagated")
	}

	if got := decisionCount(t, backend, decisionDenied) - beforeDenied; got != 0 {
		t.Errorf("denied counter rose by %v on a limiter error, want 0", got)
	}
}

// The decorator must be observation-only: it may not change what the caller
// sees, or it would silently alter enforcement.
func TestObservedPassesResultThroughUnchanged(t *testing.T) {
	want := Result{Allowed: false, Limit: 100, Remaining: 0, RetryAfter: 42}
	wantErr := errors.New("sentinel")

	got, err := Observed(stubLimiter{res: want, err: wantErr}, "test-passthrough").
		Allow(context.Background(), "caller")

	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
	if got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
}

// Observed is applied in main before injection, so a nil limiter here would
// reintroduce the nil-interface panic on the first exchange.
func TestObservedNilLimiterAllowsRequest(t *testing.T) {
	res, err := Observed(nil, "test-nil").Allow(context.Background(), "caller")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Allowed {
		t.Error("wrapping a nil limiter denied the request, want allowed")
	}
}

func TestObservedRecordsDuration(t *testing.T) {
	const backend = "test-duration"

	limiter := Observed(stubLimiter{res: Result{Allowed: true}}, backend)
	if _, err := limiter.Allow(context.Background(), "caller"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := testutil.CollectAndCount(mCheckDuration); got == 0 {
		t.Error("no rate-limit duration observations were recorded")
	}
}

func TestRecordFailOpen(t *testing.T) {
	before := testutil.ToFloat64(mFailOpen)
	RecordFailOpen()
	if got := testutil.ToFloat64(mFailOpen) - before; got != 1 {
		t.Errorf("fail_open_total rose by %v, want 1", got)
	}
}

// The metrics are only useful if they reach the default registry, which is
// what httpmetrics.ServeMetrics exposes on /metrics. Registering them
// anywhere else would make them silently unscrapable.
func TestMetricsAreExposedOnDefaultRegistry(t *testing.T) {
	if _, err := Observed(stubLimiter{res: Result{Allowed: true}}, "test-registry").
		Allow(context.Background(), "caller"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	RecordFailOpen()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering default registry: %v", err)
	}

	gathered := make(map[string]bool, len(families))
	for _, f := range families {
		gathered[f.GetName()] = true
	}

	for _, name := range []string{
		"octosts_ratelimit_decisions_total",
		"octosts_ratelimit_check_duration_seconds",
		"octosts_ratelimit_fail_open_total",
	} {
		if !gathered[name] {
			t.Errorf("%s is not exposed on the default registry", name)
		}
	}
}
