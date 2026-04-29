// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package memory

import (
	"context"
	"testing"
)

func TestGetMissReturnsNotOk(t *testing.T) {
	s := New()
	_, ok, err := s.Get(context.Background(), "no-such-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("Get on empty store: ok = true, want false")
	}
}

func TestPutThenGet(t *testing.T) {
	s := New()
	ctx := context.Background()

	if err := s.Put(ctx, "k1", 42, "scope", "id"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	id, ok, err := s.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get after Put: ok = false")
	}
	if id != 42 {
		t.Errorf("Get = %d, want 42", id)
	}
}

func TestPutOverwrites(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.Put(ctx, "k1", 42, "s", "i")
	_ = s.Put(ctx, "k1", 99, "s", "i")

	id, ok, err := s.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || id != 99 {
		t.Errorf("Get = (%d, %v), want (99, true)", id, ok)
	}
}

func TestIndependentKeys(t *testing.T) {
	s := New()
	ctx := context.Background()

	_ = s.Put(ctx, "a", 1, "s", "i")
	_ = s.Put(ctx, "b", 2, "s", "i")

	id1, _, _ := s.Get(ctx, "a")
	id2, _, _ := s.Get(ctx, "b")

	if id1 != 1 || id2 != 2 {
		t.Errorf("keys crossed: a=%d b=%d", id1, id2)
	}
}
