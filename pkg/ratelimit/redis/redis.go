// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type Limiter struct {
	limit  int
	window int
	store  redis.UniversalClient
}

var allowScript = redis.NewScript(`
local count = redis.call("INCR", KEYS[1])
if count == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[2])
end
if count > tonumber(ARGV[1]) then
  return 0
end
return 1
`)

func (l *Limiter) Allow(ctx context.Context, key string) (bool, error) {
	allowed, err := allowScript.Run(ctx, l.store, []string{key}, l.limit, l.window).Int()
	if err != nil {
		return false, fmt.Errorf("ratelimit: evaluating script for key %q: %w", key, err)
	}
	return allowed == 1, nil
}

func NewLimiter(limit int, window int, client redis.UniversalClient) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		store:  client,
	}
}
