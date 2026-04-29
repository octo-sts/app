// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package routekey

import "testing"

func TestKeyDeterministic(t *testing.T) {
	a := Key("org/repo", "bot")
	b := Key("org/repo", "bot")
	if a != b {
		t.Errorf("same inputs produced different keys: %s vs %s", a, b)
	}
}

func TestKeyDiffersByScope(t *testing.T) {
	a := Key("org/repo-a", "bot")
	b := Key("org/repo-b", "bot")
	if a == b {
		t.Errorf("different scopes produced same key: %s", a)
	}
}

func TestKeyDiffersByIdentity(t *testing.T) {
	a := Key("org/repo", "alice")
	b := Key("org/repo", "bob")
	if a == b {
		t.Errorf("different identities produced same key: %s", a)
	}
}

func TestKeyIsNonEmpty(t *testing.T) {
	if k := Key("org/repo", "bot"); k == "" {
		t.Error("Key returned empty string")
	}
}
