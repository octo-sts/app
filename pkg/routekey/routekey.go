// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package routekey

import (
	"fmt"
	"hash/fnv"
)

// Key returns a stable FNV-32a string key for a (scope, identity) pair.
// Used by the sticky store to consistently identify a routing target.
func Key(scope, identity string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope + ":" + identity))
	return fmt.Sprintf("%d", h.Sum32())
}
