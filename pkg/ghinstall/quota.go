// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"sync"
	"time"
)

// QuotaStore tracks per-installation rate-limit state, populated by a
// transport-layer tap on GitHub responses (see pkg/ghtransport).
//
// The store is a hint, not a source of truth: callers must tolerate missing
// or stale entries by falling back to capacity-blind selection. Entries older
// than the configured TTL are reported as missing.
type QuotaStore struct {
	mu    sync.RWMutex
	state map[int64]quotaSnapshot
	ttl   time.Duration
}

type quotaSnapshot struct {
	remaining int
	limit     int
	updatedAt time.Time
}

// NewQuotaStore creates a quota store. Snapshots older than ttl are treated
// as missing.
func NewQuotaStore(ttl time.Duration) *QuotaStore {
	return &QuotaStore{
		state: make(map[int64]quotaSnapshot),
		ttl:   ttl,
	}
}

// Update records a fresh quota snapshot for installID.
func (q *QuotaStore) Update(installID int64, remaining, limit int) {
	if installID == 0 || limit <= 0 {
		return
	}
	q.mu.Lock()
	q.state[installID] = quotaSnapshot{remaining, limit, time.Now()}
	q.mu.Unlock()
}

// Get returns the most recent snapshot for installID. ok is false if no
// snapshot exists or if the snapshot is older than the configured TTL.
func (q *QuotaStore) Get(installID int64) (remaining, limit int, ok bool) {
	q.mu.RLock()
	s, exists := q.state[installID]
	q.mu.RUnlock()
	if !exists {
		return 0, 0, false
	}
	if time.Since(s.updatedAt) > q.ttl {
		return 0, 0, false
	}
	return s.remaining, s.limit, true
}
