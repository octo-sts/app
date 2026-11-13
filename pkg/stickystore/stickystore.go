// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package stickystore

import (
	"context"
)

// Store persists sticky (scope, identity) -> installation ID mappings for
// checks:write policies. Implementations must be safe for concurrent use.
type Store interface {
	// Get returns the installation ID for the given key. ok is false on a
	// cache miss. A backend failure must return a non-nil err, never a miss:
	// callers fail the exchange on err, while a miss lets them assign and
	// persist a new installation for the key.
	Get(ctx context.Context, key string) (installationID int64, ok bool, err error)

	// Put persists a mapping. scope, identity, and subject are stored by
	// backends that support operator debuggability (e.g. Firestore);
	// backends that do not need them may ignore them.
	Put(ctx context.Context, key string, installationID int64, scope, identity, subject string) error
}
