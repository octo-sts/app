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
	h := fnv.New32a()
	_, _ = h.Write([]byte(scope + ":" + identity + ":" + subject))
	return fmt.Sprintf("%d", h.Sum32())
}
