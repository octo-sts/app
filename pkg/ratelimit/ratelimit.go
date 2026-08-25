// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ratelimit defines the caller rate-limiting contract shared by the
// STS server and its pluggable backends.
//
// Rate limiting here protects the shared GitHub App API quota: a single
// compromised or runaway caller must not be able to exhaust the installation
// budget and deny service to every other tenant. It is a quota-protection
// control, not an authentication control - callers are always verified before
// they are counted.
package ratelimit

import (
	"context"
	"time"
)

// Result describes a single rate-limit decision.
//
// Backends always populate Allowed. Limit, Remaining and RetryAfter are
// best-effort: a backend that cannot compute a field leaves it zero. Callers
// must not surface these values to untrusted clients, since doing so tells an
// attacker exactly how much budget remains.
type Result struct {
	// Allowed reports whether the caller may proceed.
	Allowed bool

	// Limit is the number of requests permitted per window.
	Limit int

	// Remaining is the number of requests left in the current window.
	Remaining int

	// RetryAfter is how long the caller should wait before retrying. It is
	// only meaningful when Allowed is false.
	RetryAfter time.Duration
}

// Limiter decides whether a caller identified by key may proceed.
//
// Implementations must be safe for concurrent use by multiple goroutines. A
// non-nil error means no decision could be reached (for example the backing
// store is unreachable); it is the caller's policy choice whether to fail open
// or fail closed in that case.
type Limiter interface {
	Allow(ctx context.Context, key string) (Result, error)
}

// AllowAll is a Limiter that permits every request.
//
// It is injected when rate limiting is disabled so that call sites never have
// to nil-check the interface. Using a nil Limiter instead would panic on the
// first request.
type AllowAll struct{}

// Allow implements Limiter and always permits the request.
func (AllowAll) Allow(context.Context, string) (Result, error) {
	return Result{Allowed: true}, nil
}

var _ Limiter = AllowAll{}
