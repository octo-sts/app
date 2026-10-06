// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import "regexp"

// compileAnchored compiles pattern so that it matches a value only when the
// ENTIRE value is in the pattern's language. Every pattern field in a trust
// policy and every issuer_pattern in an org allowlist goes through here, so the
// two cannot disagree on what "anchored" means.
//
// The pattern is compiled alone first: the group below hides an unbalanced ")",
// so "a)|(" would wrap to "^(?:a)|()$", whose "()$" alternative matches every
// value. Standalone, "a)|(" is a syntax error. A legitimate top-level "a|b"
// still compiles.
//
// The non-capturing group is required: "|" binds looser than the anchors, so
// "^"+p+"$" parses as "(^A)|(B$)" and leaves each alternative anchored at one
// end only (GHSA-mwqh-2vg8-rhj3). The group also scopes inline flags such as
// (?m) to the pattern, so the outer "^" and "$" always mean start and end of
// text, the same as \A and \z.
func compileAnchored(pattern string) (*regexp.Regexp, error) {
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, err
	}
	return regexp.Compile("^(?:" + pattern + ")$")
}
