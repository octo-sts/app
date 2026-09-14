// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestCompile(t *testing.T) {
	tests := []struct {
		name    string
		tp      *TrustPolicy
		wantErr bool
	}{{
		name: "valid literals",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		wantErr: false,
	}, {
		name: "valid patterns",
		tp: &TrustPolicy{
			IssuerPattern:  "https://(example|google)\\.com",
			SubjectPattern: "[0-9]{10}",
			ClaimPattern: map[string]string{
				"email": ".*@example.com",
			},
		},
		wantErr: false,
	}, {
		name: "multiple issuers",
		tp: &TrustPolicy{
			Issuer:        "https://example.com",
			IssuerPattern: ".*",
			Subject:       "asdf",
		},
		wantErr: true,
	}, {
		name: "multiple subjects",
		tp: &TrustPolicy{
			Issuer:         "https://example.com",
			Subject:        "subject",
			SubjectPattern: ".*",
		},
		wantErr: true,
	}, {
		name: "invalid issuer pattern",
		tp: &TrustPolicy{
			IssuerPattern: ")(",
			Subject:       "asdf",
		},
		wantErr: true,
	}, {
		name: "invalid subject pattern",
		tp: &TrustPolicy{
			Issuer:         "https://examples.com",
			SubjectPattern: ")(",
		},
		wantErr: true,
	}, {
		name: "invalid audience pattern",
		tp: &TrustPolicy{
			Issuer:          "https://examples.com",
			Subject:         "asdf",
			AudiencePattern: ")(",
		},
		wantErr: true,
	}, {
		name: "invalid claim pattern",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
			ClaimPattern: map[string]string{
				"claim": ")()",
			},
		},
		wantErr: true,
	}, {
		name: "missing issuer",
		tp: &TrustPolicy{
			Subject: "subject",
		},
		wantErr: true,
	}, {
		name: "missing subject",
		tp: &TrustPolicy{
			Issuer: "https://example.com",
		},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.tp.Compile(); (err != nil) != tt.wantErr {
				t.Errorf("Compile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPatternAnchoringWithAlternation locks in full anchoring for patterns
// containing a top-level "|": "^"+p+"$" would parse as "(^A)|(B$)", letting
// "main|develop" match the subject "main-attacker" as a prefix (or
// "attacker-develop" as a suffix). See compileAnchored.
func TestPatternAnchoringWithAlternation(t *testing.T) {
	tp := &TrustPolicy{
		Issuer:         "https://example.com",
		SubjectPattern: "main|develop",
		ClaimPattern: map[string]string{
			"ref": "refs/heads/main|refs/tags/v1",
		},
	}
	if err := tp.Compile(); err != nil {
		t.Fatalf("Compile() = %v", err)
	}

	token := func(sub string) *oidc.IDToken {
		return &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  sub,
			Audience: []string{"octo-sts.dev"},
		}
	}

	for _, sub := range []string{"main", "develop"} {
		tok := token(sub)
		withClaims(tok, []byte(`{"ref":"refs/heads/main"}`))
		if _, err := tp.CheckToken(tok, "octo-sts.dev"); err != nil {
			t.Errorf("CheckToken(%q) = %v, wanted match", sub, err)
		}
	}

	// Prefix/suffix leakage through the unanchored alternatives.
	for _, sub := range []string{"main-attacker", "attacker-develop", "xmainx"} {
		tok := token(sub)
		withClaims(tok, []byte(`{"ref":"refs/heads/main"}`))
		if _, err := tp.CheckToken(tok, "octo-sts.dev"); err == nil {
			t.Errorf("CheckToken(%q) matched, wanted rejection", sub)
		}
	}

	// Claim patterns must be anchored the same way: a branch named
	// "x/refs/tags/v1" yields this ref, which must not match the
	// "refs/tags/v1" alternative as a suffix.
	tok := token("main")
	withClaims(tok, []byte(`{"ref":"refs/heads/x/refs/tags/v1"}`))
	if _, err := tp.CheckToken(tok, "octo-sts.dev"); err == nil {
		t.Error("CheckToken with suffix-matching ref claim matched, wanted rejection")
	}
}

// TestCompileRejectsGroupEscape verifies a pattern with an unbalanced ")" is
// rejected outright rather than silently rewritten by the "(?:" wrapper into
// "^(?:foo)|()$", whose "()$" alternative matches everything.
func TestCompileRejectsGroupEscape(t *testing.T) {
	tp := &TrustPolicy{
		Issuer:         "https://example.com",
		SubjectPattern: `foo)|(`,
	}
	if err := tp.Compile(); err == nil {
		t.Error("Compile() = nil, wanted error for unbalanced group")
	}
}

func TestCheckToken(t *testing.T) {
	tests := []struct {
		name    string
		tp      *TrustPolicy
		token   *oidc.IDToken
		claims  []byte
		wantErr bool
	}{{
		name: "valid token",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "subject",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: false,
	}, {
		name: "invalid issuer",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.org",
			Subject:  "subject",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "invalid subject",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "asdf",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "invalid audience",
		tp: &TrustPolicy{
			Issuer:   "https://example.com",
			Subject:  "subject",
			Audience: "octo-sts.com",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "asdf",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "valid patterns",
		tp: &TrustPolicy{
			IssuerPattern:  "https://(example|google)\\.com",
			SubjectPattern: "[0-9]{10}",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "1234567890",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: false,
	}, {
		name: "invalid issuer pattern",
		tp: &TrustPolicy{
			IssuerPattern: "https://(example|google)\\.com",
			Subject:       "blah",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.org",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "invalid subject pattern",
		tp: &TrustPolicy{
			Issuer:         "https://example.com",
			SubjectPattern: "[0-9]{10}",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "invalid audience pattern",
		tp: &TrustPolicy{
			Issuer:          "https://example.com",
			Subject:         "blah",
			AudiencePattern: "octo-sts\\.com",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev", "octo-sts.co"},
		},
		wantErr: true,
	}, {
		name: "missing custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
			ClaimPattern: map[string]string{
				"email": ".*@example.com",
			},
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.com",
			Subject: "subject",
			// No email claim.
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "reject prefix (with ^$)",
		tp: &TrustPolicy{
			Issuer:         "https://accounts.google.com",
			SubjectPattern: "^(123|456)$",
		},
		token: &oidc.IDToken{
			Issuer:   "https://accounts.google.com",
			Subject:  "123999",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "reject prefix (without ^$)",
		tp: &TrustPolicy{
			Issuer:         "https://accounts.google.com",
			SubjectPattern: "(123|456)",
		},
		token: &oidc.IDToken{
			Issuer:   "https://accounts.google.com",
			Subject:  "123999",
			Audience: []string{"octo-sts.dev"},
		},
		wantErr: true,
	}, {
		name: "matches one of audience pattern",
		tp: &TrustPolicy{
			Issuer:          "https://example.com",
			Subject:         "blah",
			AudiencePattern: "(octo|nona)-sts\\.dev",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"deka-sts.dev", "nona-sts.dev"},
		},
		wantErr: false,
	}, {
		name: "matches one of audience",
		tp: &TrustPolicy{
			Issuer:          "https://example.com",
			Subject:         "blah",
			AudiencePattern: "example.com",
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev", "deka-sts.dev", "example.com", "nona-sts.dev"},
		},
		wantErr: false,
	}, {
		name: "matching boolean claims",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email_verified": "true",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email_verified": true}`),
		wantErr: false,
	}, {
		name: "matching custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email": ".*@example.com",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email": "test@example.com"}`),
		wantErr: false,
	}, {
		name: "matching multiple custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email":  ".*@example.com",
				"domain": ".*\\.net",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email": "test@example.com", "domain": "example.net", "extra": "extra"}`),
		wantErr: false,
	}, {
		name: "missing custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email_verified": "true",
				"email":          ".*@example.com",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email_verified": true}`),
		wantErr: true,
	}, {
		name: "number custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"age": "\\d+",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"age": 21}`),
		wantErr: true,
	}, {
		name: "mismatching custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email": ".*@example.com",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email": "test@example.dev"}`),
		wantErr: true,
	}, {
		name: "mismatching one of multiple custom claim",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "blah",
			ClaimPattern: map[string]string{
				"email":  ".*@example.com",
				"domain": ".*\\.net",
			},
		},
		token: &oidc.IDToken{
			Issuer:   "https://example.com",
			Subject:  "blah",
			Audience: []string{"octo-sts.dev"},
		},
		claims:  []byte(`{"email": "test@example.dev", "domain": "example.net"}`),
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.tp.Compile(); err != nil {
				t.Fatalf("Compile() = %v", err)
			}
			withClaims(tt.token, tt.claims)
			if _, err := tt.tp.CheckToken(tt.token, "octo-sts.dev"); (err != nil) != tt.wantErr {
				t.Errorf("CheckToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// reflect hack because "claims" field is unexported by oidc IDToken
// https://github.com/coreos/go-oidc/pull/329
func withClaims(token *oidc.IDToken, data []byte) {
	val := reflect.Indirect(reflect.ValueOf(token))
	member := val.FieldByName("claims")
	pointer := unsafe.Pointer(member.UnsafeAddr())
	realPointer := (*[]byte)(pointer)
	*realPointer = data
}

// TestCheckTokenPatternsMatchWholeValue is the regression test for
// GHSA-mwqh-2vg8-rhj3. A pattern must accept a value only when the ENTIRE value
// is in the pattern's language. Anchoring as "^"+p+"$" broke that whenever p had
// a top-level "|": "|" binds looser than the anchors, so "^A|B$" is "(^A)|(B$)"
// and A leaked as a prefix while B leaked as a suffix. An inline "(?m)" in p
// broke it too, by turning the trailing "$" into an end-of-line anchor.
func TestCheckTokenPatternsMatchWholeValue(t *testing.T) {
	const (
		ghIssuer = "https://token.actions.githubusercontent.com"
		mainRef  = "repo:org/app:ref:refs/heads/main"
		devRef   = "repo:org/app:ref:refs/heads/develop"
	)
	tests := []struct {
		name    string
		tp      *TrustPolicy
		token   *oidc.IDToken
		claims  []byte
		wantErr bool
	}{{
		name:  "subject alternation accepts first alternative",
		tp:    &TrustPolicy{Issuer: ghIssuer, SubjectPattern: mainRef + "|" + devRef},
		token: &oidc.IDToken{Issuer: ghIssuer, Subject: mainRef, Audience: []string{"octo-sts.dev"}},
	}, {
		name:  "subject alternation accepts last alternative",
		tp:    &TrustPolicy{Issuer: ghIssuer, SubjectPattern: mainRef + "|" + devRef},
		token: &oidc.IDToken{Issuer: ghIssuer, Subject: devRef, Audience: []string{"octo-sts.dev"}},
	}, {
		name:    "subject alternation rejects prefix extension of first alternative",
		tp:      &TrustPolicy{Issuer: ghIssuer, SubjectPattern: mainRef + "|" + devRef},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: mainRef + "-x", Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}, {
		name:    "subject alternation rejects suffix extension of last alternative",
		tp:      &TrustPolicy{Issuer: ghIssuer, SubjectPattern: mainRef + "|" + devRef},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "evil:" + devRef, Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}, {
		name:    "subject trailing empty alternative does not accept everything",
		tp:      &TrustPolicy{Issuer: ghIssuer, SubjectPattern: mainRef + "|"},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "repo:org/evil:ref:refs/heads/main", Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}, {
		name:  "issuer alternation accepts last alternative",
		tp:    &TrustPolicy{IssuerPattern: `https://token\.actions\.githubusercontent\.com|https://gitlab\.com`, Subject: "s"},
		token: &oidc.IDToken{Issuer: "https://gitlab.com", Subject: "s", Audience: []string{"octo-sts.dev"}},
	}, {
		name:    "issuer alternation rejects prefix extension of first alternative",
		tp:      &TrustPolicy{IssuerPattern: `https://token\.actions\.githubusercontent\.com|https://gitlab\.com`, Subject: "s"},
		token:   &oidc.IDToken{Issuer: ghIssuer + ".evil.example", Subject: "s", Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}, {
		name:    "issuer trailing empty alternative does not accept everything",
		tp:      &TrustPolicy{IssuerPattern: `https://token\.actions\.githubusercontent\.com|`, Subject: "s"},
		token:   &oidc.IDToken{Issuer: "https://evil.example", Subject: "s", Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}, {
		name:  "audience alternation accepts first alternative",
		tp:    &TrustPolicy{Issuer: ghIssuer, Subject: "s", AudiencePattern: `octo-sts\.dev|sts\.example\.com`},
		token: &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
	}, {
		name:    "audience alternation rejects suffix extension of last alternative",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", AudiencePattern: `octo-sts\.dev|sts\.example\.com`},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"evil.sts.example.com"}},
		wantErr: true,
	}, {
		name:    "audience trailing empty alternative does not accept everything",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", AudiencePattern: `octo-sts\.dev|`},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"evil.example"}},
		wantErr: true,
	}, {
		name:   "claim alternation accepts last alternative",
		tp:     &TrustPolicy{Issuer: ghIssuer, Subject: "s", ClaimPattern: map[string]string{"ref": "refs/heads/main|refs/tags/v1"}},
		token:  &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
		claims: []byte(`{"ref": "refs/tags/v1"}`),
	}, {
		name:    "claim alternation rejects prefix extension of first alternative",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", ClaimPattern: map[string]string{"ref": "refs/heads/main|refs/tags/v1"}},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
		claims:  []byte(`{"ref": "refs/heads/main-x"}`),
		wantErr: true,
	}, {
		name:    "claim alternation rejects suffix extension of last alternative",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", ClaimPattern: map[string]string{"ref": "refs/heads/main|refs/tags/v1"}},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
		claims:  []byte(`{"ref": "refs/heads/x/refs/tags/v1"}`),
		wantErr: true,
	}, {
		name:    "claim trailing empty alternative does not accept everything",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", ClaimPattern: map[string]string{"ref": "refs/heads/main|"}},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
		claims:  []byte(`{"ref": "refs/heads/evil"}`),
		wantErr: true,
	}, {
		name:    "claim inline multiline flag does not unanchor the end",
		tp:      &TrustPolicy{Issuer: ghIssuer, Subject: "s", ClaimPattern: map[string]string{"ref": "(?m)refs/heads/main"}},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: "s", Audience: []string{"octo-sts.dev"}},
		claims:  []byte(`{"ref": "refs/heads/main\nrefs/heads/evil"}`),
		wantErr: true,
	}, {
		name:  "parenthesized alternation keeps accepting its alternatives",
		tp:    &TrustPolicy{Issuer: ghIssuer, SubjectPattern: "(?:" + mainRef + "|" + devRef + ")"},
		token: &oidc.IDToken{Issuer: ghIssuer, Subject: devRef, Audience: []string{"octo-sts.dev"}},
	}, {
		name:    "parenthesized alternation keeps rejecting extensions",
		tp:      &TrustPolicy{Issuer: ghIssuer, SubjectPattern: "(?:" + mainRef + "|" + devRef + ")"},
		token:   &oidc.IDToken{Issuer: ghIssuer, Subject: mainRef + "-x", Audience: []string{"octo-sts.dev"}},
		wantErr: true,
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.tp.Compile(); err != nil {
				t.Fatalf("Compile() = %v", err)
			}
			withClaims(tt.token, tt.claims)
			if _, err := tt.tp.CheckToken(tt.token, "octo-sts.dev"); (err != nil) != tt.wantErr {
				t.Errorf("CheckToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTrustPolicyCompileRejectsGroupEscape covers a bypass the anchoring group
// would CREATE if the pattern were not compiled on its own first. An unbalanced
// ")" in p closes "^(?:" early: "a)|(" wraps to "^(?:a)|()$", whose "()$"
// alternative accepts every value. Standalone, "a)|(" is a syntax error, so
// compiling p alone rejects it before it is wrapped.
func TestTrustPolicyCompileRejectsGroupEscape(t *testing.T) {
	for _, pat := range []string{`a)|(`, `token\.example\.com)|(`} {
		// The bypass exists only because the wrapped form compiles. If Go ever
		// rejected it, this row would pass for the wrong reason.
		if _, err := regexp.Compile("^(?:" + pat + ")$"); err != nil {
			t.Fatalf("wrapped %q no longer compiles (%v); this row no longer demonstrates the bypass", pat, err)
		}

		fields := []struct {
			name string
			tp   *TrustPolicy
		}{
			{"issuer_pattern", &TrustPolicy{IssuerPattern: pat, Subject: "s"}},
			{"subject_pattern", &TrustPolicy{Issuer: "https://example.com", SubjectPattern: pat}},
			{"audience_pattern", &TrustPolicy{Issuer: "https://example.com", Subject: "s", AudiencePattern: pat}},
			{"claim_pattern", &TrustPolicy{Issuer: "https://example.com", Subject: "s", ClaimPattern: map[string]string{"ref": pat}}},
		}
		for _, tt := range fields {
			t.Run(pat+"/"+tt.name, func(t *testing.T) {
				err := tt.tp.Compile()
				if err == nil {
					t.Fatalf("Compile() = nil error for %s %q, want a rejection", tt.name, pat)
				}
				if !strings.Contains(err.Error(), tt.name) {
					t.Errorf("Compile() error = %q, want it to name %s", err, tt.name)
				}
			})
		}
	}

	// A legitimate top-level alternation must still compile.
	if err := (&TrustPolicy{Issuer: "https://example.com", SubjectPattern: "a|b"}).Compile(); err != nil {
		t.Errorf("Compile() with subject_pattern \"a|b\" = %v, want nil", err)
	}
}
