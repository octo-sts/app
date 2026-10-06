// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import "testing"

// TestCompileAnchored pins the property every pattern field relies on: the
// compiled regexp accepts a value only when the ENTIRE value is in the pattern's
// language. Each row names a way the naive "^"+p+"$" form broke that, or a
// pattern shape the fix must leave unchanged.
func TestCompileAnchored(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		accept  []string
		reject  []string
	}{{
		name:    "top-level alternation anchors both alternatives",
		pattern: "main|develop",
		accept:  []string{"main", "develop"},
		reject:  []string{"main-x", "x-develop", "xmainx", ""},
	}, {
		name:    "trailing empty alternative accepts only the alternative or empty",
		pattern: "main|",
		accept:  []string{"main", ""},
		reject:  []string{"x", "main-x"},
	}, {
		name:    "inline multiline flag stays scoped to the pattern",
		pattern: "(?m)main",
		accept:  []string{"main"},
		reject:  []string{"main\nx", "x\nmain"},
	}, {
		name:    "inline case-insensitive flag applies",
		pattern: "(?i)MAIN",
		accept:  []string{"main", "MAIN"},
		reject:  []string{"mainx"},
	}, {
		name:    "author-written anchors are harmless",
		pattern: "^main$",
		accept:  []string{"main"},
		reject:  []string{"xmain"},
	}, {
		name:    "parenthesized alternation is unchanged",
		pattern: "(?:main|develop)",
		accept:  []string{"main", "develop"},
		reject:  []string{"main-x"},
	}, {
		name:    "empty pattern accepts only the empty value",
		pattern: "",
		accept:  []string{""},
		reject:  []string{"x"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, err := compileAnchored(tt.pattern)
			if err != nil {
				t.Fatalf("compileAnchored(%q) = %v", tt.pattern, err)
			}
			for _, v := range tt.accept {
				if !re.MatchString(v) {
					t.Errorf("pattern %q rejected %q, want accept", tt.pattern, v)
				}
			}
			for _, v := range tt.reject {
				if re.MatchString(v) {
					t.Errorf("pattern %q accepted %q, want reject", tt.pattern, v)
				}
			}
		})
	}
}

// TestCompileAnchoredRejectsInvalidPatterns: a pattern that fails to compile on
// its own is rejected even when the wrapped form would compile, because an
// unbalanced ")" would otherwise close the anchoring group early.
func TestCompileAnchoredRejectsInvalidPatterns(t *testing.T) {
	for _, pat := range []string{`a)|(`, `token\.example\.com)|(`, `[unclosed`, `*a`} {
		if re, err := compileAnchored(pat); err == nil {
			t.Errorf("compileAnchored(%q) = %q, want an error", pat, re.String())
		}
	}
}
