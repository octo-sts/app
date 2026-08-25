// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Decision label values recorded on the decisions counter.
const (
	decisionAllowed = "allowed"
	decisionDenied  = "denied"
	decisionError   = "error"
)

// These register into the default Prometheus registry, which is what
// httpmetrics.ServeMetrics already exposes on /metrics, so no extra wiring is
// needed to scrape them.
//
// The caller key is deliberately never a label. It is unbounded - one value
// per repository - and using it would multiply Prometheus series without
// bound. Per-caller attribution belongs in logs, not metrics.
var (
	mDecisions = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "octosts_ratelimit_decisions_total",
			Help: "Caller rate-limit decisions, by backend and outcome (allowed, denied, error).",
		},
		[]string{"backend", "decision"},
	)

	mCheckDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "octosts_ratelimit_check_duration_seconds",
			Help: "Latency of the caller rate-limit check, which sits on the token exchange hot path.",
			// Wide enough to span an in-process map lookup (microseconds)
			// and a cross-region Redis round trip (tens of milliseconds).
			Buckets: []float64{
				0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
				0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1,
			},
		},
		[]string{"backend"},
	)

	mFailOpen = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "octosts_ratelimit_fail_open_total",
			Help: "Exchanges admitted without a rate-limit decision because the limiter errored and OCTOSTS_RATE_LIMIT_FAIL_OPEN is set. A sustained non-zero rate means the GitHub App quota is currently unprotected.",
		},
	)
)

// RecordFailOpen records that an exchange was admitted despite the limiter
// failing, because the deployment is configured to fail open.
//
// This is a separate metric rather than a decision label because it answers a
// different question: not "was this caller over budget?" but "how many
// requests bypassed the limiter entirely?". That number should be alerted on.
func RecordFailOpen() {
	mFailOpen.Inc()
}

// Observed wraps l so that every decision and its latency are recorded to
// Prometheus under the given backend label ("memory", "redis").
//
// It is applied at construction rather than inside each backend so that
// backends stay free of metrics plumbing and every implementation, including
// future ones, is instrumented identically.
func Observed(l Limiter, backend string) Limiter {
	if l == nil {
		l = AllowAll{}
	}
	return &observedLimiter{inner: l, backend: backend, now: time.Now}
}

type observedLimiter struct {
	inner   Limiter
	backend string
	now     func() time.Time
}

// Allow implements Limiter, recording the outcome before returning it
// unchanged. It never alters the decision.
func (o *observedLimiter) Allow(ctx context.Context, key string) (Result, error) {
	start := o.now()
	res, err := o.inner.Allow(ctx, key)
	mCheckDuration.WithLabelValues(o.backend).Observe(o.now().Sub(start).Seconds())

	decision := decisionAllowed
	switch {
	case err != nil:
		decision = decisionError
	case !res.Allowed:
		decision = decisionDenied
	}
	mDecisions.WithLabelValues(o.backend, decision).Inc()

	return res, err
}

var _ Limiter = (*observedLimiter)(nil)
