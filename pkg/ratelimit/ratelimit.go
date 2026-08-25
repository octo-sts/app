// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ratelimit

import "context"

type Limiter interface {
	Allow(ctx context.Context, key string) (bool, error)
}
