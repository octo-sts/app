// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package logtest

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/chainguard-dev/clog"
)

// Capture returns a context whose clog logger writes to the returned buffer.
func Capture(t testing.TB) (context.Context, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	return clog.WithLogger(t.Context(), clog.New(slog.NewTextHandler(&logs, nil))), &logs
}
