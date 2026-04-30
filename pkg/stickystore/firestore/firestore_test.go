// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package firestore

import (
	"testing"
	"time"
)

func TestDocFields(t *testing.T) {
	d := doc{
		InstallationID: 12345,
		Scope:          "org/repo",
		Identity:       "bot",
		Subject:        "repo:org/mono:ref:refs/heads/main",
		CreatedAt:      time.Now(),
		ExpireAt:       time.Now().Add(720 * time.Hour),
	}
	if d.InstallationID != 12345 {
		t.Errorf("InstallationID = %d, want 12345", d.InstallationID)
	}
	if d.Scope != "org/repo" {
		t.Errorf("Scope = %q, want org/repo", d.Scope)
	}
	if d.Subject != "repo:org/mono:ref:refs/heads/main" {
		t.Errorf("Subject = %q, want repo:org/mono:ref:refs/heads/main", d.Subject)
	}
}

func TestNewStoreFields(t *testing.T) {
	s := New(nil, "my-collection", 30*24*time.Hour)
	if s.collection != "my-collection" {
		t.Errorf("collection = %q, want my-collection", s.collection)
	}
	if s.ttl != 30*24*time.Hour {
		t.Errorf("ttl = %v, want 720h", s.ttl)
	}
}
