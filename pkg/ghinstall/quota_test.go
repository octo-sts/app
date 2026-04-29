// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghinstall

import (
	"testing"
	"time"
)

func TestQuotaStoreGetMissing(t *testing.T) {
	q := NewQuotaStore(time.Minute)
	if _, _, ok := q.Get(123); ok {
		t.Errorf("Get on empty store: ok = true, want false")
	}
}

func TestQuotaStoreUpdateGet(t *testing.T) {
	q := NewQuotaStore(time.Minute)
	q.Update(123, 4500, 15000)

	rem, lim, ok := q.Get(123)
	if !ok {
		t.Fatalf("Get after Update: ok = false, want true")
	}
	if rem != 4500 || lim != 15000 {
		t.Errorf("Get returned (%d, %d), want (4500, 15000)", rem, lim)
	}
}

func TestQuotaStoreOverwrite(t *testing.T) {
	q := NewQuotaStore(time.Minute)
	q.Update(123, 1000, 15000)
	q.Update(123, 9999, 15000)

	rem, _, ok := q.Get(123)
	if !ok {
		t.Fatalf("Get: ok = false")
	}
	if rem != 9999 {
		t.Errorf("Get remaining = %d, want 9999 (latest)", rem)
	}
}

func TestQuotaStoreStale(t *testing.T) {
	q := NewQuotaStore(50 * time.Millisecond)
	q.Update(123, 4500, 15000)

	// Fresh — should be visible.
	if _, _, ok := q.Get(123); !ok {
		t.Fatalf("immediate Get: ok = false, want true")
	}

	// Wait past TTL.
	time.Sleep(80 * time.Millisecond)
	if _, _, ok := q.Get(123); ok {
		t.Errorf("Get past TTL: ok = true, want false")
	}
}

func TestQuotaStoreIgnoreInvalid(t *testing.T) {
	q := NewQuotaStore(time.Minute)
	// installID 0 is invalid (uninitialized) — must be a no-op.
	q.Update(0, 5000, 15000)
	if _, _, ok := q.Get(0); ok {
		t.Errorf("Get(0) after Update(0, ...): ok = true, want false (must ignore)")
	}

	// limit <= 0 is invalid — must be a no-op.
	q.Update(123, 5000, 0)
	if _, _, ok := q.Get(123); ok {
		t.Errorf("Get(123) after Update with limit=0: ok = true, want false (must ignore)")
	}
}
