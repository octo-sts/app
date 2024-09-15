// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"reflect"
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
