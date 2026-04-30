// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package routekey

import "testing"

func TestKeyDeterministic(t *testing.T) {
	a := Key("org/repo", "bot", "sub:1")
	b := Key("org/repo", "bot", "sub:1")
	if a != b {
		t.Errorf("same inputs produced different keys: %s vs %s", a, b)
	}
}

func TestKeyDiffersByScope(t *testing.T) {
	a := Key("org/repo-a", "bot", "sub:1")
	b := Key("org/repo-b", "bot", "sub:1")
	if a == b {
		t.Errorf("different scopes produced same key: %s", a)
	}
}

func TestKeyDiffersByIdentity(t *testing.T) {
	a := Key("org/repo", "alice", "sub:1")
	b := Key("org/repo", "bob", "sub:1")
	if a == b {
		t.Errorf("different identities produced same key: %s", a)
	}
}

func TestKeyDiffersBySubject(t *testing.T) {
	a := Key("org/repo", "bot", "repo:org/mono:ref:refs/heads/main")
	b := Key("org/repo", "bot", "repo:org/mono:ref:refs/heads/feature")
	if a == b {
		t.Errorf("different subjects produced same key: %s", a)
	}
}

func TestKeyIsNonEmpty(t *testing.T) {
	if k := Key("org/repo", "bot", "sub:1"); k == "" {
		t.Error("Key returned empty string")
	}
}
