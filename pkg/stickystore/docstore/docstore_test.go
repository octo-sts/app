// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package docstore

import (
	"context"
	"testing"
	"time"

	"gocloud.dev/docstore"
	_ "gocloud.dev/docstore/memdocstore"
)

// openMem returns an in-memory docstore.Collection keyed on the "key" field.
// memdocstore lets us exercise the full code path (including the TTL refresh)
// without touching a real cloud backend.
func openMem(t *testing.T) *docstore.Collection {
	t.Helper()
	coll, err := docstore.OpenCollection(context.Background(), "mem://sticky/key")
	if err != nil {
		t.Fatalf("OpenCollection: %v", err)
	}
	t.Cleanup(func() { coll.Close() })
	return coll
}

func TestGetMissReturnsNotOk(t *testing.T) {
	s := New(openMem(t), time.Minute)
	_, ok, err := s.Get(context.Background(), "no-such-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("Get on empty store: ok = true, want false")
	}
}

func TestPutThenGet(t *testing.T) {
	s := New(openMem(t), time.Minute)
	ctx := context.Background()

	if err := s.Put(ctx, "k1", 42, "scope", "id", "sub"); err != nil {
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
	s := New(openMem(t), time.Minute)
	ctx := context.Background()

	_ = s.Put(ctx, "k1", 42, "s", "i", "sub")
	_ = s.Put(ctx, "k1", 99, "s", "i", "sub")

	id, ok, err := s.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || id != 99 {
		t.Errorf("Get = (%d, %v), want (99, true)", id, ok)
	}
}

func TestIndependentKeys(t *testing.T) {
	s := New(openMem(t), time.Minute)
	ctx := context.Background()

	_ = s.Put(ctx, "a", 1, "s", "i", "sub")
	_ = s.Put(ctx, "b", 2, "s", "i", "sub")

	id1, _, _ := s.Get(ctx, "a")
	id2, _, _ := s.Get(ctx, "b")

	if id1 != 1 || id2 != 2 {
		t.Errorf("keys crossed: a=%d b=%d", id1, id2)
	}
}

// TestRefreshTTLBumpsExpireAt verifies the refresh helper bumps expire_at.
// Invoked directly (not via Get) to avoid coupling the test to Get's
// asynchronous refresh goroutine.
func TestRefreshTTLBumpsExpireAt(t *testing.T) {
	coll := openMem(t)
	s := New(coll, time.Hour)
	ctx := context.Background()

	if err := s.Put(ctx, "k1", 42, "s", "i", "sub"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	before := doc{Key: "k1"}
	if err := coll.Get(ctx, &before); err != nil {
		t.Fatalf("raw Get before: %v", err)
	}

	time.Sleep(10 * time.Millisecond)
	s.refreshTTL(ctx, "k1")

	after := doc{Key: "k1"}
	if err := coll.Get(ctx, &after); err != nil {
		t.Fatalf("raw Get after: %v", err)
	}

	if !after.ExpireAt.After(before.ExpireAt) {
		t.Errorf("expire_at was not refreshed: before=%v after=%v", before.ExpireAt, after.ExpireAt)
	}
}
