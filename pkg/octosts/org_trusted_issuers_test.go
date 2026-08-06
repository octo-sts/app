// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const testGitHubIssuer = "https://token.actions.githubusercontent.com"

func TestCompileMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     Mode
		wantMode Mode
		wantErr  string
	}{
		{name: "empty defaults to enforce", mode: "", wantMode: ModeEnforce},
		{name: "explicit enforce", mode: ModeEnforce, wantMode: ModeEnforce},
		{name: "explicit audit", mode: ModeAudit, wantMode: ModeAudit},
		{name: "unknown", mode: Mode("Enforce"), wantErr: "unknown mode"},
		{name: "garbage", mode: Mode("off"), wantErr: "unknown mode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &OrgTrustedIssuers{Mode: tc.mode, Issuers: []string{testGitHubIssuer}}
			got, err := c.Compile()
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Compile() = nil error, want %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Compile() error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile() = %v, want nil", err)
			}
			if got.Mode() != tc.wantMode {
				t.Errorf("Mode() = %q, want %q", got.Mode(), tc.wantMode)
			}
		})
	}
}

func TestCompileRequiresAtLeastOneEntry(t *testing.T) {
	// A present-but-empty file must be an error, not a silent deny-all.
	c := &OrgTrustedIssuers{Mode: ModeEnforce}
	if _, err := c.Compile(); err == nil {
		t.Fatal("Compile() = nil error for empty config, want an error")
	}
}

func TestAllowsExactMatch(t *testing.T) {
	c := &OrgTrustedIssuers{Issuers: []string{testGitHubIssuer, "https://accounts.google.com"}}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{testGitHubIssuer, true},
		{"https://accounts.google.com", true},
		{"https://evil.example.com", false},
		{"", false},
		// byte-exact: a trailing slash is a different issuer
		{"https://accounts.google.com/", false},
	} {
		if got := a.Allows(tc.issuer); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.issuer, got, tc.want)
		}
	}
}

// TestAllowsIsCaseSensitive pins the documented invariant. A future change to
// case-insensitive comparison would widen the allowlist, so it must fail here.
func TestAllowsIsCaseSensitive(t *testing.T) {
	c := &OrgTrustedIssuers{Issuers: []string{testGitHubIssuer}}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	for _, iss := range []string{
		"https://TOKEN.actions.githubusercontent.com",
		"HTTPS://token.actions.githubusercontent.com",
		"https://Token.Actions.GithubUserContent.com",
	} {
		if a.Allows(iss) {
			t.Errorf("Allows(%q) = true, want false — matching must be case-sensitive", iss)
		}
	}
}

func TestAllowsPatternMatch(t *testing.T) {
	c := &OrgTrustedIssuers{
		IssuerPatterns: []string{
			`https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+`,
			`https://login\.microsoftonline\.com/[a-f0-9-]+/v2\.0`,
		},
	}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	for _, tc := range []struct {
		issuer string
		want   bool
	}{
		{"https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF123456", true},
		{"https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0", true},
		{"https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF123456/extra", false},
		{"https://not-eks.example.com/id/ABC", false},
	} {
		if got := a.Allows(tc.issuer); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.issuer, got, tc.want)
		}
	}
}

// TestAnchoringRejectsAlternationBypass is the reason patterns are wrapped in
// a non-capturing group. With the naive "^"+p+"$" form, "|" binds looser than
// the anchors so "^A|B$" parses as "(^A)|(B$)" and the pattern is effectively
// unanchored. This is the ONLY case that distinguishes "^(?:p)$" from "^p$".
func TestAnchoringRejectsAlternationBypass(t *testing.T) {
	c := &OrgTrustedIssuers{
		IssuerPatterns: []string{`https://a\.example\.com|https://b\.example\.com`},
	}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	if a.Allows("https://a.example.com.attacker.example/x") {
		t.Error("Allows() permitted a suffix-extended host — alternation pattern is not anchored")
	}
	for _, ok := range []string{"https://a.example.com", "https://b.example.com"} {
		if !a.Allows(ok) {
			t.Errorf("Allows(%q) = false, want true", ok)
		}
	}
}

// TestAnchoringRejectsSuffixBypass regresses an unanchored bare MatchString. It
// passes under BOTH "^p$" and "^(?:p)$", so it does not exercise the alternation
// fix — keep it alongside TestAnchoringRejectsAlternationBypass.
func TestAnchoringRejectsSuffixBypass(t *testing.T) {
	c := &OrgTrustedIssuers{
		IssuerPatterns: []string{`https://token\.actions\.githubusercontent\.com`},
	}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v", err)
	}
	if a.Allows("https://token.actions.githubusercontent.com.evil.example.com") {
		t.Error("Allows() permitted a suffix-extended host — pattern is not anchored")
	}
}

func TestCompileRejectsBadPattern(t *testing.T) {
	c := &OrgTrustedIssuers{IssuerPatterns: []string{"[unclosed"}}
	_, err := c.Compile()
	if err == nil {
		t.Fatal("Compile() = nil error for an uncompilable pattern, want an error")
	}
	if !strings.Contains(err.Error(), "invalid issuer_pattern") {
		t.Errorf("Compile() error = %q, want it to mention invalid issuer_pattern", err)
	}
}

func TestCompileAllowsInlineFlags(t *testing.T) {
	c := &OrgTrustedIssuers{IssuerPatterns: []string{`(?i)https://token\.actions\.githubusercontent\.com`}}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v, want nil (inline flags are permitted)", err)
	}
	if !a.Allows("https://TOKEN.actions.githubusercontent.com") {
		t.Error("Allows() = false, want true for a (?i) pattern")
	}
}

func TestAllowsUnionOfBothLists(t *testing.T) {
	c := &OrgTrustedIssuers{
		Issuers:        []string{testGitHubIssuer},
		IssuerPatterns: []string{`https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+`},
	}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v, want nil (both lists may be populated)", err)
	}
	if !a.Allows(testGitHubIssuer) {
		t.Error("exact entry not matched when both lists are present")
	}
	if !a.Allows("https://oidc.eks.eu-west-1.amazonaws.com/id/ZZZ999") {
		t.Error("pattern entry not matched when both lists are present")
	}
}

func TestCompileValidatesIssuers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		issuer  string
		wantErr string
	}{
		// Delegated to oidcvalidate.IsValidIssuer — assert delegation, do not
		// re-test its whole surface here.
		{name: "http on non-loopback", issuer: "http://evil.example.com", wantErr: "invalid issuer"},
		{name: "no host", issuer: "https://", wantErr: "invalid issuer"},
		{name: "query string", issuer: "https://example.com?a=b", wantErr: "invalid issuer"},
		{name: "userinfo", issuer: "https://u:p@example.com", wantErr: "invalid issuer"},
		{name: "non-ascii host", issuer: "https://exämple.com", wantErr: "invalid issuer"},
		// Our own additional rule: byte-exact matching means an uppercase
		// authority would silently never match a real iss claim.
		{name: "uppercase host", issuer: "https://Accounts.Google.com", wantErr: "must be lowercase"},
		// Verified: oidcvalidate.IsValidIssuer ACCEPTS "HTTPS://..." because
		// url.Parse lowercases the scheme. Only the raw-string check catches it.
		{name: "uppercase scheme", issuer: "HTTPS://accounts.google.com", wantErr: "must be lowercase"},
		{name: "uppercase scheme and host", issuer: "HTTPS://Accounts.Google.com", wantErr: "must be lowercase"},
		// These exercise the authority-truncation branch (a "/" after the host)
		// while uppercase is present; every other uppercase row has no path, so
		// the arithmetic would otherwise only see lowercase input.
		{name: "uppercase host with path", issuer: "https://Example.com/foo", wantErr: "must be lowercase"},
		{name: "uppercase scheme with path", issuer: "HTTPS://example.com/foo", wantErr: "must be lowercase"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &OrgTrustedIssuers{Issuers: []string{tc.issuer}}
			_, err := c.Compile()
			if err == nil {
				t.Fatalf("Compile() = nil error for %q, want %q", tc.issuer, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Compile() error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestCompileAcceptsRealWorldIssuers pins the issuers operators actually use.
// Trailing slashes are legal iss values (Auth0 tenants publish them), so
// rejecting them would push those orgs onto issuer_patterns, the strictly more
// dangerous surface.
func TestCompileAcceptsRealWorldIssuers(t *testing.T) {
	issuers := []string{
		"https://token.actions.githubusercontent.com",
		"https://accounts.google.com",
		"https://gitlab.com",
		"https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF123456",
		"https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
		"https://tenant.us.auth0.com/",
		// IsValidIssuer permits http on loopback for local development.
		"http://localhost",
		"http://127.0.0.1",
	}
	for _, iss := range issuers {
		c := &OrgTrustedIssuers{Issuers: []string{iss}}
		a, err := c.Compile()
		if err != nil {
			t.Errorf("Compile() rejected real-world issuer %q: %v", iss, err)
			continue
		}
		if !a.Allows(iss) {
			t.Errorf("Allows(%q) = false for its own entry", iss)
		}
	}
}

func TestCompileEnforcesCaps(t *testing.T) {
	mk := func(n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, fmt.Sprintf("https://issuer-%d.example.com", i))
		}
		return out
	}
	mkPat := func(n int) []string {
		out := make([]string, 0, n)
		for i := range n {
			out = append(out, fmt.Sprintf(`https://pattern-%d\.example\.com`, i))
		}
		return out
	}

	if _, err := (&OrgTrustedIssuers{Issuers: mk(maxIssuers)}).Compile(); err != nil {
		t.Errorf("Compile() with %d issuers = %v, want nil", maxIssuers, err)
	}
	if _, err := (&OrgTrustedIssuers{Issuers: mk(maxIssuers + 1)}).Compile(); err == nil {
		t.Errorf("Compile() with %d issuers = nil error, want an error", maxIssuers+1)
	}
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: mkPat(maxIssuerPatterns)}).Compile(); err != nil {
		t.Errorf("Compile() with %d patterns = %v, want nil", maxIssuerPatterns, err)
	}
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: mkPat(maxIssuerPatterns + 1)}).Compile(); err == nil {
		t.Errorf("Compile() with %d patterns = nil error, want an error", maxIssuerPatterns+1)
	}

	// Pattern length is a boundary PAIR like the two counts above: exactly at
	// the cap must compile, one over must fail. Testing only the failing side
	// would let an off-by-one (>= instead of >) through.
	atCap := strings.Repeat("a", maxPatternLen)
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{atCap}}).Compile(); err != nil {
		t.Errorf("Compile() with a %d-char pattern = %v, want nil", len(atCap), err)
	}
	overCap := strings.Repeat("a", maxPatternLen+1)
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{overCap}}).Compile(); err == nil {
		t.Errorf("Compile() with a %d-char pattern = nil error, want an error", len(overCap))
	}
}

func TestParseOrgTrustedIssuers(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		// wantErr is a substring of the expected error; empty means success.
		// Asserting the substring rather than just err != nil is what pins
		// WHICH layer rejected the input — see the singular-key row below.
		wantErr  string
		wantMode Mode
	}{
		{
			name: "valid enforce by default",
			raw: `
issuers:
  - https://token.actions.githubusercontent.com
`,
			wantMode: ModeEnforce,
		},
		{
			name: "valid audit",
			raw: `
mode: audit
issuers:
  - https://token.actions.githubusercontent.com
issuer_patterns:
  - https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+
`,
			wantMode: ModeAudit,
		},
		{
			// UnmarshalStrict must reject the singular typo the plural field
			// names invite. The valid issuers entry is load-bearing: without it
			// a lenient Unmarshal would drop the unknown key and STILL error
			// from Compile's at-least-one-entry check, so the row would pass
			// while testing nothing. Asserting "unknown field" pins the layer.
			name: "unknown key issuer_pattern singular",
			raw: `
issuers:
  - https://token.actions.githubusercontent.com
issuer_pattern:
  - https://token\.actions\.githubusercontent\.com
`,
			wantErr: "unknown field",
		},
		{
			name:    "unknown key entirely",
			raw:     "enabled: true\nissuers:\n  - https://a.example.com\n",
			wantErr: "unknown field",
		},
		{name: "malformed yaml", raw: "issuers: [\n", wantErr: "parsing organization trusted issuers"},
		{name: "empty document", raw: "", wantErr: "must list at least one entry"},
		{name: "uncompilable pattern", raw: "issuer_patterns:\n  - \"[unclosed\"\n", wantErr: "invalid issuer_pattern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := ParseOrgTrustedIssuers([]byte(tc.raw))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseOrgTrustedIssuers() = nil error, want one containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ParseOrgTrustedIssuers() error = %q, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseOrgTrustedIssuers() = %v, want nil", err)
			}
			if a.Mode() != tc.wantMode {
				t.Errorf("Mode() = %q, want %q", a.Mode(), tc.wantMode)
			}
		})
	}
}

// TestCompileRejectsWildcardDot pins the footgun that motivated the check: the
// most natural way to write "any subdomain of example.com" is also a complete
// bypass of the organization control.
func TestCompileRejectsWildcardDot(t *testing.T) {
	for _, pat := range []string{
		`https://.*.example.com`,
		// A partially hardened pattern: the varying label is bounded but the
		// separators are not, so "." still matches "-" and this permits the
		// attacker-registrable "https://evil-example.com". This shape is the
		// one that stays broken if the scanner never leaves a character class.
		`https://[a-z0-9-]+.example.com`,
		// A bare "." with no repetition operator is just as loose per byte.
		`https://ci.example\.com`,
	} {
		c := &OrgTrustedIssuers{
			Issuers: []string{testGitHubIssuer},
			IssuerPatterns: []string{
				`https://a\.example\.com`,
				`https://b\.example\.com`,
				pat,
			},
		}
		_, err := c.Compile()
		if err == nil {
			t.Fatalf("Compile() with pattern %q = nil error, want an error", pat)
		}
		// The index tells an operator which of up to 16 patterns is at fault,
		// and the corrected form has to be in the message or the error does not
		// teach the fix.
		for _, want := range []string{"issuer_patterns[2]", `\.`, "[a-z0-9-]+"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Compile() with pattern %q: error = %q, want it contain %q", pat, err, want)
			}
		}
	}
}

// TestAllowsLabelBoundedPatternRejectsBypass regresses the bypass itself, not
// merely the banned character: the corrected pattern must still express the
// intent while refusing both hosts the loose form permitted.
func TestAllowsLabelBoundedPatternRejectsBypass(t *testing.T) {
	c := &OrgTrustedIssuers{IssuerPatterns: []string{`https://[a-z0-9-]+\.example\.com`}}
	a, err := c.Compile()
	if err != nil {
		t.Fatalf("Compile() = %v, want nil", err)
	}
	if !a.Allows("https://ci.example.com") {
		t.Error(`Allows("https://ci.example.com") = false, want true`)
	}
	for _, iss := range []string{
		// ".*" consumed "evil.attacker" and the unescaped "." matched "-".
		"https://evil.attacker-example.com",
		// ".*" also crossed the "/", so an unrelated host matched.
		"https://totally-evil.com/x?a=example.com",
	} {
		if a.Allows(iss) {
			t.Errorf("Allows(%q) = true, want false — wildcard crossed a DNS or path boundary", iss)
		}
	}
}

// TestCompileRejectsSlashMatchingAtoms covers the bypasses that a name-based
// scan for "." could never catch. Every pattern here was verified to compile
// under the old check AND to match the attacker-controlled issuer below, which
// is the whole point: the atom does not have to be spelled "." to behave like
// one.
func TestCompileRejectsSlashMatchingAtoms(t *testing.T) {
	// Each row carries the issuer it wrongly permitted. In every case the host
	// is attacker-controlled and the pattern only reaches "example.com" by
	// letting its varying atom consume the "/".
	const spanning = "https://totally-evil.com/x.example.com"

	for _, tc := range []struct {
		name string
		pat  string
		evil string
	}{
		{"escaped non-whitespace shorthand", `https://\S+\.example\.com`, spanning},
		{"whitespace union class", `https://[\s\S]+\.example\.com`, spanning},
		{"negated newline class", `https://[^\n]+\.example\.com`, spanning},
		{"posix ascii class", `https://[[:ascii:]]+\.example\.com`, spanning},
		{"posix graph class", `https://[[:graph:]]+\.example\.com`, spanning},
		// "/" is 0x2F, which falls inside the range "." (0x2E) to "9" (0x39).
		// No list of NAMED constructs catches this one; only asking the atom
		// whether it matches "/" does. The class admits digits and separators
		// only, so the demonstration host is built from those.
		{"range that spans the slash byte", `https://[.-9]+\.example\.com`, "https://1/2.example.com"},
		// Unicode punctuation includes "/", and so does POSIX punct.
		{"unicode punctuation class", `https://\p{P}+\.example\.com`, "https://-/-.example.com"},
		{"posix punct class", `https://[[:punct:]]+\.example\.com`, "https://-/-.example.com"},
		// A loose atom AFTER an escaped literal. Treating "\." as a reason to
		// stop scanning — rather than as two bytes to skip — would let everything
		// downstream of the first escape through unchecked.
		{"loose atom after an escaped literal", `https://a\.\S+\.example\.com`, "https://a.evil.com/x.example.com"},
		// A loose atom after a bracket expression, for the same reason.
		{"loose atom after a bracket expression", `https://[a-z]+\.\S+\.example\.com`, "https://a.evil.com/x.example.com"},
		// RE2 reads a first-position "]" as a literal, so "[^]]" is "any byte
		// except ]" — including "/". Scanning for the first "]" instead extracts
		// the uncompilable "[^]" and left the class untested.
		{"negated class with a leading literal ]", `https://[^]]+\.example\.com`, "https://evil.com/x.example.com"},
		{"class whose leading literal ] precedes a slash", `https://[]/]+\.example\.com`, "https:///.example.com"},
		// Numeric escapes SPELL "/" rather than naming a class, so treating them
		// as escaped literals skipped two bytes and left the digits to be read as
		// unexamined literal text. All three of these are "/".
		// "[:" opens a POSIX class only when a ":]" follows; without one RE2 reads
		// the "[" as an ordinary member and the class keeps going, so these are
		// ordinary classes that happen to contain "/". The scanner used to give up
		// on the whole pattern here, which is how they passed.
		{"pseudo-POSIX class spanning slash to tilde", `https://[[:/-~]+\.example\.com`, "https://e/v/i/l/x.example.com"},
		{"pseudo-POSIX class holding a literal slash", `https://[[:/]+\.example\.com`, "https:///.example.com"},
		{"pseudo-POSIX class after a member", `https://[a[:/]+\.example\.com`, "https://a/a.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Confirm the pattern really is a bypass, so the test fails loudly if
			// a future edit makes the row vacuous.
			if re, err := regexp.Compile("^(?:" + tc.pat + ")$"); err != nil {
				t.Fatalf("regexp.Compile(%q) = %v; the row must be a valid regexp", tc.pat, err)
			} else if !re.MatchString(tc.evil) {
				t.Fatalf("pattern %q does not match %q; the row no longer demonstrates a bypass", tc.pat, tc.evil)
			}

			c := &OrgTrustedIssuers{
				Issuers: []string{testGitHubIssuer},
				IssuerPatterns: []string{
					`https://a\.example\.com`,
					`https://b\.example\.com`,
					tc.pat,
				},
			}
			_, err := c.Compile()
			if err == nil {
				t.Fatalf("Compile() with pattern %q = nil error, want an error", tc.pat)
			}
			for _, want := range []string{"issuer_patterns[2]", `"/"`, "[a-z0-9-]+"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Compile() with pattern %q: error = %q, want it to contain %q", tc.pat, err, want)
				}
			}
		})
	}
}

// TestCompileRejectsPatternsThatEscapeTheAnchoringGroup covers a bypass the
// non-capturing group CREATES rather than prevents.
//
// Wrapping p in "^(?:" + p + ")$" anchors a top-level alternation, but an
// unbalanced ")" inside p closes that group early: "token\.example\.com)|("
// becomes "^(?:token\.example\.com)|()$", whose "()$" alternative matches every
// string — allow-all, and the webhook reported the file Valid. Compiling p on its
// own first rejects it, because standalone it is a syntax error.
func TestCompileRejectsPatternsThatEscapeTheAnchoringGroup(t *testing.T) {
	// Both rows must be patterns whose WRAPPED form compiles — that is what makes
	// them bypasses rather than ordinary syntax errors. A bare ")" does not
	// qualify: "^(?:))$" is itself invalid, so the pre-existing wrapped compile
	// already rejected it.
	for _, pat := range []string{
		`token\.example\.com)|(`,
		`a)|(`,
	} {
		t.Run(pat, func(t *testing.T) {
			// The bypass only exists because the WRAPPED form compiles. If Go ever
			// rejected it, this row would pass for the wrong reason.
			if _, err := regexp.Compile("^(?:" + pat + ")$"); err != nil {
				t.Fatalf("wrapped %q no longer compiles (%v); this row no longer demonstrates the bypass", pat, err)
			}
			al, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile()
			if err == nil {
				t.Fatalf("Compile() with pattern %q = nil error, want a rejection; Allows(%q) = %v",
					pat, "https://totally-evil.example", al.Allows("https://totally-evil.example"))
			}
		})
	}

	// The group must still do its job: a legitimate top-level alternation stays
	// accepted and stays anchored.
	al, err := (&OrgTrustedIssuers{
		IssuerPatterns: []string{`https://a\.example\.com|https://b\.example\.com`},
	}).Compile()
	if err != nil {
		t.Fatalf("Compile() with a legitimate top-level alternation = %v, want nil", err)
	}
	for iss, want := range map[string]bool{
		"https://a.example.com":             true,
		"https://b.example.com":             true,
		"https://a.example.com.evil":        false,
		"evil-prefix-https://a.example.com": false,
	} {
		if got := al.Allows(iss); got != want {
			t.Errorf("Allows(%q) = %v, want %v — the alternation must stay anchored at both ends", iss, got, want)
		}
	}
}

// TestCompileRejectsSeparatorUnderQuantifier covers the half the per-atom scan
// structurally cannot: a "/" that only spans because of the structure AROUND it.
//
// Every atom in "([a-z0-9.-]+/)*" is innocent alone, so the atom scan passes it —
// yet the group repeats across separators. "?", "{n,m}", "+" and alternation do the
// same. In each case the host is attacker-chosen and the trusted name is demoted to
// a path segment, while the pattern still matches its author's intended issuer,
// which is exactly why it reads as safe.
//
// This test used to assert these were ACCEPTED, as a documented limitation. A
// reviewer asked for the class closed rather than documented, so it now asserts
// rejection; checkNoSeparatorUnderQuantifier walks the regexp/syntax tree.
func TestCompileRejectsSeparatorUnderQuantifier(t *testing.T) {
	for _, tc := range []struct{ name, pat, spanning string }{
		{"star", `https://([a-z0-9.-]+/)*trusted\.example\.com`, "https://evil.com/x/trusted.example.com"},
		{"plus", `https://([a-z0-9.-]+/)+trusted\.example\.com`, "https://evil.com/x/trusted.example.com"},
		{"optional", `https://(x\.com/)?trusted\.example\.com`, "https://x.com/trusted.example.com"},
		{"bounded repeat", `https://([a-z0-9.-]+/){1,3}trusted\.example\.com`, "https://evil.com/x/trusted.example.com"},
		{"alternation", `https://(good\.example\.com|evil\.com/x/trusted\.example\.com)`, "https://evil.com/x/trusted.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Prove the shape really is a bypass, so the row cannot go vacuous.
			re, err := regexp.Compile("^(?:" + tc.pat + ")$")
			if err != nil {
				t.Fatalf("regexp.Compile(%q) = %v; the row must be a valid regexp", tc.pat, err)
			}
			if !re.MatchString(tc.spanning) {
				t.Fatalf("pattern %q does not match %q; the row no longer demonstrates spanning", tc.pat, tc.spanning)
			}

			_, err = (&OrgTrustedIssuers{IssuerPatterns: []string{tc.pat}}).Compile()
			if err == nil {
				t.Fatalf("Compile() with pattern %q = nil error, want a rejection", tc.pat)
			}
			if !strings.Contains(err.Error(), "repetition, optional or alternation") {
				t.Errorf("Compile() error = %q, want the separator-under-quantifier message", err)
			}
		})
	}
}

// TestCompileKeepsFixedPositionSlashes is the other half: the check must not reject a
// "/" at a FIXED position, or it would break every real issuer with a path. All of
// these appear in the fixtures, the README or the schema examples.
func TestCompileKeepsFixedPositionSlashes(t *testing.T) {
	for _, pat := range []string{
		`https://host\.example\.com/id/[A-Z0-9]+`,
		`https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+`,
		`https://example\.com/realms/[a-z0-9-]+`,
		`https://login\.microsoftonline\.com/[a-f0-9-]+/v2\.0`,
		// An alternation with no separator in it stays legal: the check keys on the
		// "/" being under variable structure, not on the structure alone.
		`https://a\.example\.com|https://b\.example\.com`,
	} {
		if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile(); err != nil {
			t.Errorf("Compile() with pattern %q = %v, want nil", pat, err)
		}
	}
}

// TestCompileRejectsAnUnparseablePattern pins that a pattern the AST check cannot
// analyze is still rejected — the property survives, it just moved layers.
//
// checkPatternCannotSpanHost returns nil when syntax.Parse fails, so the rejection
// comes from the subsequent regexp.Compile instead of a "cannot verify" message from
// the guard. That branch used to exist because a hand-written scanner could
// mis-delimit an atom it had itself extracted; parsing with regexp/syntax removes the
// failure mode rather than reporting it.
func TestCompileRejectsAnUnparseablePattern(t *testing.T) {
	// Assembled at runtime so staticcheck does not constant-fold the pattern and
	// report the invalid class as a lint error — being invalid is the point.
	pat := `https://[[:` + strings.Repeat("bogus", 1) + `:]]+\.example\.com`
	if _, err := regexp.Compile(pat); err == nil {
		t.Fatalf("regexp.Compile(%q) = nil error; this test needs a pattern Go rejects", pat)
	}
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile(); err == nil {
		t.Fatalf("Compile() with pattern %q = nil error, want a rejection", pat)
	}
}

// TestCompileAllowsNumericEscapesForSlashAtAFixedPosition records a DELIBERATE
// loosening that came with moving to AST analysis.
//
// The byte scanner treated "\x2F", "\x{2F}" and "\057" as opaque escapes and rejected
// them wherever they appeared. regexp/syntax folds them into an OpLiteral containing
// "/", indistinguishable from a typed "/" — because that is what they are. So they are
// now allowed at a fixed position, on the same rule that permits
// https://host\.example\.com/id/[A-Z0-9]+.
//
// That is safe for the reason the fixed-position rule is safe: the "/" cannot repeat or
// be skipped, so the pattern still matches exactly one host. Asserted below, so this
// stays a reasoned allowance rather than an accident.
func TestCompileAllowsNumericEscapesForSlashAtAFixedPosition(t *testing.T) {
	for _, pat := range []string{
		`https://a\x2Fb\.example\.com`,
		`https://a\x{2F}b\.example\.com`,
		`https://a\057b\.example\.com`,
	} {
		al, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile()
		if err != nil {
			t.Fatalf("Compile() with pattern %q = %v, want nil", pat, err)
		}
		// It spells exactly one issuer, and cannot reach an attacker-chosen host.
		if !al.Allows("https://a/b.example.com") {
			t.Errorf("pattern %q does not match the issuer it spells", pat)
		}
		for _, evil := range []string{
			"https://evil.com/b.example.com",
			"https://a/x/b.example.com",
			"https://evil.com/a/b.example.com",
		} {
			if al.Allows(evil) {
				t.Errorf("pattern %q permitted %q — a fixed-position escape must not span", pat, evil)
			}
		}
	}
}

// TestCompileAcceptsPosixClassesThatCannotMatchSlash is the other half of the
// empirical claim: the check must not blanket-reject POSIX classes. Which ones
// are safe was determined by compiling each class and testing it against "/" —
// alpha, lower, upper, alnum, word, digit and xdigit do not match "/", while
// ascii, punct, graph and print do.
func TestCompileAcceptsPosixClassesThatCannotMatchSlash(t *testing.T) {
	for _, class := range []string{"[[:alpha:]]", "[[:lower:]]", "[[:alnum:]]", "[[:word:]]", "[[:digit:]]"} {
		pat := `https://` + class + `+\.example\.com`
		if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile(); err != nil {
			t.Errorf("Compile() with pattern %q = %v, want nil — %s cannot match %q", pat, err, class, "/")
		}
	}
}

// TestCompileAllowsLiteralSlashInRealWorldPatterns pins that the check does not
// reject a literal "/". Both patterns ship in the fixtures, README and schema
// examples, and both contain a path.
func TestCompileAllowsLiteralSlashInRealWorldPatterns(t *testing.T) {
	for _, tc := range []struct{ pat, issuer string }{
		{`https://oidc\.eks\.[a-z0-9-]+\.amazonaws\.com/id/[A-Z0-9]+`, "https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF0123456789"},
		{`https://login\.microsoftonline\.com/[a-f0-9-]+/v2\.0`, "https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/v2.0"},
	} {
		a, err := (&OrgTrustedIssuers{IssuerPatterns: []string{tc.pat}}).Compile()
		if err != nil {
			t.Fatalf("Compile() with pattern %q = %v, want nil", tc.pat, err)
		}
		if !a.Allows(tc.issuer) {
			t.Errorf("Allows(%q) = false, want true for pattern %q", tc.issuer, tc.pat)
		}
	}
}

// TestCompileBracketExtractionHandlesEscapedCloseBracket pins that an escaped "]"
// does not terminate a bracket expression. A mis-parse flips the verdict: read
// correctly the atom is `[a-z\]]`, which cannot match "/" and must be accepted;
// read as closing early it becomes `[a-z\]` and the rest misparses.
func TestCompileBracketExtractionHandlesEscapedCloseBracket(t *testing.T) {
	const pat = `https://[a-z\]]+\.example\.com`
	if regexp.MustCompile(`^[a-z\]]$`).MatchString("/") {
		t.Fatal(`[a-z\]] matches "/"; the premise of this test is wrong`)
	}
	a, err := (&OrgTrustedIssuers{IssuerPatterns: []string{pat}}).Compile()
	if err != nil {
		t.Fatalf("Compile() with pattern %q = %v, want nil", pat, err)
	}
	if !a.Allows("https://ci]x.example.com") {
		t.Error(`Allows("https://ci]x.example.com") = false, want true`)
	}
}

func TestCompileAllowsDotInsideCharacterClass(t *testing.T) {
	for _, p := range []string{
		`https://a[.]example\.com`,
		`https://[a-z.]+\.example\.com`,
		// An escaped "]" does not close the class, so the "." that follows it
		// is still inside one. Mis-parsing "\]" as a closing bracket would put
		// this "." outside a class and wrongly reject the pattern.
		`https://[a-z\].]+\.example\.com`,
	} {
		if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{p}}).Compile(); err != nil {
			t.Errorf("Compile() with pattern %q = %v, want nil", p, err)
		}
	}
}

// TestCompileRejectsBadPatternBeforeDotCheck pins that an unterminated class is
// still reported by regexp's own compile error rather than being swallowed by
// the wildcard-dot scan, which must not treat "[unclosed" as leaving a class.
func TestCompileRejectsBadPatternWithCompileError(t *testing.T) {
	_, err := (&OrgTrustedIssuers{IssuerPatterns: []string{"[unclosed"}}).Compile()
	if err == nil {
		t.Fatal("Compile() = nil error, want error")
	}
	if !strings.Contains(err.Error(), "invalid issuer_pattern") {
		t.Errorf("Compile() error = %q, want regexp's compile error", err)
	}
	if strings.Contains(err.Error(), "can match") {
		t.Errorf("Compile() error = %q, want the compile error, not the atom error", err)
	}
}

// TestCompileRejectsALoosePatternThatIsAlsoMalformed replaces an ordering pin that no
// longer applies. It used to require the looseness error to beat regexp's compile
// error for a pattern that is both loose and malformed. The span check now needs a
// successful parse, so a malformed pattern reports the compile error instead — the
// verdict is unchanged and still fail-closed, only the message differs.
func TestCompileRejectsALoosePatternThatIsAlsoMalformed(t *testing.T) {
	if _, err := (&OrgTrustedIssuers{IssuerPatterns: []string{`https://.*.example.com(`}}).Compile(); err == nil {
		t.Fatal("Compile() = nil error, want a rejection")
	}
}
