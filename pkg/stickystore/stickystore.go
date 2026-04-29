// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"context"
	"fmt"
	"hash/fnv"
)

// Store persists sticky (scope, identity) -> installation ID mappings for
// checks:write policies. Implementations must be safe for concurrent use.
type Store interface {
	// Get returns the installation ID for the given key. ok is false on
	// cache miss or if the backend is unreachable (callers fall back to
	// round-robin).
	Get(ctx context.Context, key string) (installationID int64, ok bool, err error)

	// Put persists a mapping. scope and identity are stored by backends
	// that support operator debuggability (e.g. Firestore); backends that
	// do not need them may ignore them.
	Put(ctx context.Context, key string, installationID int64, scope, identity string) error
}

// Key returns a stable hash key for (scope, identity) using FNV-32a.
func Key(scope, identity string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope + ":" + identity))
	return fmt.Sprintf("%d", h.Sum32())
}
