// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"os"
	"testing"
	"time"
)

// TestMain shortens the waits before re-reading a trust policy 404 for every
// test in this package. The re-reads still happen, so a fake GitHub that
// answers 404 sees 1+len(notFoundRereadDelays) contents requests, but no test
// sleeps for the real ~4s. Tests that need other waits set
// notFoundRereadDelays themselves and restore it with t.Cleanup.
func TestMain(m *testing.M) {
	notFoundRereadDelays = []time.Duration{time.Millisecond, time.Millisecond}
	os.Exit(m.Run())
}
