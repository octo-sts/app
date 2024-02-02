// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"testing"

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
		wantErr bool
	}{{
		name: "valid token",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		wantErr: false,
	}, {
		name: "invalid issuer",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.org",
			Subject: "subject",
		},
		wantErr: true,
	}, {
		name: "invalid subject",
		tp: &TrustPolicy{
			Issuer:  "https://example.com",
			Subject: "subject",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.com",
			Subject: "asdf",
		},
		wantErr: true,
	}, {
		name: "valid patterns",
		tp: &TrustPolicy{
			IssuerPattern:  "https://(example|google)\\.com",
			SubjectPattern: "[0-9]{10}",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.com",
			Subject: "1234567890",
		},
		wantErr: false,
	}, {
		name: "invalid issuer pattern",
		tp: &TrustPolicy{
			IssuerPattern: "https://(example|google)\\.com",
			Subject:       "blah",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.org",
			Subject: "blah",
		},
		wantErr: true,
	}, {
		name: "invalid subject pattern",
		tp: &TrustPolicy{
			Issuer:         "https://example.com",
			SubjectPattern: "[0-9]{10}",
		},
		token: &oidc.IDToken{
			Issuer:  "https://example.com",
			Subject: "blah",
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
		},
		wantErr: true,
	}}

	// TODO(mattmoor): Figure out how to test custom claims with IDToken.
	// - Test for extra custom claims,
	// - Test for matching a custom claim,
	// - Test for mismatching a custom claim,
	// - Test for matching multiple custom claims,
	// - Test for mismatching one of several custom claims.
	// - Test for a non-string custom claim.

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.tp.Compile(); err != nil {
				t.Fatalf("Compile() = %v", err)
			}
			if _, err := tt.tp.CheckToken(tt.token); (err != nil) != tt.wantErr {
				t.Errorf("CheckToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
