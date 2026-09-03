// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package routekey

import (
	"fmt"
	"hash/fnv"
)

// Key returns a stable FNV-32a string key for a (scope, identity, subject)
// tuple. Using subject gives each distinct caller its own sticky mapping,
// improving distribution across installations while preserving check-run
// ownership.
func Key(scope, identity, subject string) string {
	return fmt.Sprintf("%d", sum(scope, identity, subject))
}

// Index maps a (scope, identity, subject) tuple to a stable index in [0, n),
// so the same caller always lands on the same slot without shared state.
func Index(scope, identity, subject string, n int) int {
	return int(sum(scope, identity, subject) % uint32(n)) //nolint:gosec // n is a small positive count
}

func sum(scope, identity, subject string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope + ":" + identity + ":" + subject))
	return h.Sum32()
}
