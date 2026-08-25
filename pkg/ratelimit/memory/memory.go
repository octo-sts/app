// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sync"
	"time"
)

type Quota struct {
	Budget   int       `json:"budget"`
	ResetsAt time.Time `json:"resetsAt"`
}

type Limiter struct {
	limit  int
	window int
	store  map[string]Quota // map of key to Quota
	mu     sync.Mutex
}

func (m *Limiter) Allow(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	quota, exists := m.store[key]
	if !exists {
		m.store[key] = Quota{
			Budget:   m.limit - 1,
			ResetsAt: time.Now().Add(time.Duration(m.window)),
		}
		return true, nil
	}

	if time.Now().After(quota.ResetsAt) {
		m.store[key] = Quota{
			Budget:   m.limit - 1,
			ResetsAt: time.Now().Add(time.Duration(m.window)),
		}
		return true, nil
	}

	if quota.Budget > 0 {
		quota.Budget--
		m.store[key] = quota
		return true, nil
	}

	return false, nil
}

func NewLimiter(limit int, window int) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		store:  make(map[string]Quota),
	}
}
