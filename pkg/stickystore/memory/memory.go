// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"sync"
)

// Store is an in-memory implementation of stickystore.
type Store struct {
	mu sync.RWMutex
	m  map[string]int64
}

// New creates an in-memory sticky store.
func New() *Store {
	return &Store{m: make(map[string]int64)}
}

// Get returns the installation ID for key, or ok=false if not present.
func (s *Store) Get(_ context.Context, key string) (int64, bool, error) {
	s.mu.RLock()
	id, ok := s.m[key]
	s.mu.RUnlock()
	return id, ok, nil
}

// Put stores a mapping. scope and identity are ignored by this implementation.
func (s *Store) Put(_ context.Context, key string, installationID int64, _, _ string) error {
	s.mu.Lock()
	s.m[key] = installationID
	s.mu.Unlock()
	return nil
}
