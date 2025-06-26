// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package oidcvalidate

import (
	"strings"
	"testing"
)

func TestIsValidIssuer(t *testing.T) {
	tests := []struct {
		name     string
		issuer   string
		expected bool
	}{
		// Valid cases
		{
			name:     "valid HTTPS issuer",
			issuer:   "https://example.com",
			expected: true,
		},
		{
			name:     "valid HTTPS issuer with path",
			issuer:   "https://example.com/path",
			expected: true,
		},
		{
			name:     "valid HTTPS issuer with nested path",
			issuer:   "https://example.com/auth/realms/master",
			expected: true,
		},
		{
			name:     "valid HTTPS issuer with port",
			issuer:   "https://example.com:8443",
			expected: true,
		},
		{
			name:     "valid localhost HTTP (testing)",
			issuer:   "http://localhost:8080",
			expected: true,
		},
		{
			name:     "valid 127.0.0.1 HTTP (testing)",
			issuer:   "http://127.0.0.1:8080",
			expected: true,
		},
		{
			name:     "valid IPv6 localhost HTTP (testing)",
			issuer:   "http://[::1]:8080",
			expected: true,
		},

		// Invalid cases - basic validation
		{
			name:     "empty issuer",
			issuer:   "",
			expected: false,
		},
		{
			name:     "invalid URL",
			issuer:   "not-a-url",
			expected: false,
		},
		{
			name:     "issuer too long",
			issuer:   "https://" + strings.Repeat("a", 300) + ".com",
			expected: false,
		},

		// Invalid cases - scheme validation
		{
			name:     "HTTP issuer (not localhost)",
			issuer:   "http://example.com",
			expected: false,
		},
		{
			name:     "FTP scheme",
			issuer:   "ftp://example.com",
			expected: false,
		},
		{
			name:     "missing scheme",
			issuer:   "example.com",
			expected: false,
		},

		// Valid cases - trailing slash (real-world compatibility)
		{
			name:     "issuer with trailing slash",
			issuer:   "https://example.com/",
			expected: true,
		},
		{
			name:     "issuer with path and trailing slash",
			issuer:   "https://example.com/path/",
			expected: true,
		},

		// Invalid cases - query and fragment (RFC 8414 violation)
		{
			name:     "issuer with query parameter",
			issuer:   "https://example.com?param=value",
			expected: false,
		},
		{
			name:     "issuer with fragment",
			issuer:   "https://example.com#fragment",
			expected: false,
		},
		{
			name:     "issuer with path query and fragment",
			issuer:   "https://example.com/path?query=value#fragment",
			expected: false,
		},
		{
			name:     "endpoint manipulation with fragment",
			issuer:   "https://example.com/controllablepath#",
			expected: false,
		},

		// Invalid cases - userinfo
		{
			name:     "issuer with userinfo",
			issuer:   "https://user:pass@example.com",
			expected: false,
		},
		{
			name:     "issuer with username only",
			issuer:   "https://user@example.com",
			expected: false,
		},

		// Invalid cases - path traversal
		{
			name:     "issuer with path traversal",
			issuer:   "https://example.com/../admin",
			expected: false,
		},
		{
			name:     "issuer with path traversal in middle",
			issuer:   "https://example.com/auth/../admin",
			expected: false,
		},

		// Invalid cases - control characters
		{
			name:     "issuer with newline in hostname",
			issuer:   "https://example\n.com",
			expected: false,
		},
		{
			name:     "issuer with tab in hostname",
			issuer:   "https://example\t.com",
			expected: false,
		},
		{
			name:     "issuer with space in hostname",
			issuer:   "https://example .com",
			expected: false,
		},

		// Invalid cases - malformed URLs
		{
			name:     "issuer without host",
			issuer:   "https://",
			expected: false,
		},
		{
			name:     "issuer with invalid characters in path",
			issuer:   "https://example.com/<script>",
			expected: false,
		},

		// Real-world attack scenarios
		{
			name:     "issuer with empty fragment (original attack)",
			issuer:   "https://example.com/controllablepath#",
			expected: false,
		},
		{
			name:     "issuer with percent encoding",
			issuer:   "https://example.com/path%2F..%2Fadmin",
			expected: false,
		},
		{
			name:     "issuer with normal path",
			issuer:   "https://example.com/admin",
			expected: true,
		},
		{
			name:     "issuer with port and path",
			issuer:   "https://keycloak.example.com:8443/auth/realms/master",
			expected: true,
		},

		// Path regex edge cases
		{
			name:     "issuer with double slashes in path",
			issuer:   "https://example.com//admin",
			expected: false,
		},
		{
			name:     "issuer with triple slashes in path",
			issuer:   "https://example.com///admin",
			expected: false,
		},
		{
			name:     "issuer with double tildes",
			issuer:   "https://example.com/path~~backup",
			expected: false,
		},
		{
			name:     "issuer ending with tilde (backup file)",
			issuer:   "https://example.com/config~",
			expected: false,
		},
		{
			name:     "issuer with single dot segment",
			issuer:   "https://example.com/./admin",
			expected: false,
		},
		{
			name:     "issuer with tilde segment",
			issuer:   "https://example.com/~/admin",
			expected: false,
		},
		{
			name:     "issuer with very long path segment",
			issuer:   "https://example.com/" + strings.Repeat("a", 151),
			expected: false,
		},
		{
			name:     "issuer with valid single tilde in path",
			issuer:   "https://example.com/user~name/path",
			expected: true,
		},

		// Homograph/IDN attacks
		{
			name:     "issuer with Unicode characters (umlaut)",
			issuer:   "https://exämple.com",
			expected: false,
		},
		{
			name:     "issuer with Unicode circled characters",
			issuer:   "https://eⓍample.com",
			expected: false,
		},
		{
			name:     "issuer with Cyrillic characters",
			issuer:   "https://еxample.com", // Cyrillic 'е' instead of Latin 'e'
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidIssuer(tt.issuer)
			if result != tt.expected {
				t.Errorf("IsValidIssuer(%q) = %v, expected %v", tt.issuer, result, tt.expected)
			}
		})
	}
}

func TestIsValidSubject(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		expected bool
	}{
		// Valid subjects according to OIDC spec
		{
			name:     "valid alphanumeric subject",
			subject:  "user123",
			expected: true,
		},
		{
			name:     "valid UUID subject",
			subject:  "550e8400-e29b-41d4-a716-446655440000",
			expected: true,
		},
		{
			name:     "valid numeric subject",
			subject:  "1234567890",
			expected: true,
		},
		{
			name:     "valid subject with hyphen and underscore",
			subject:  "user-name_123",
			expected: true,
		},
		{
			name:     "valid subject with dots",
			subject:  "user.name.123",
			expected: true,
		},
		{
			name:     "valid long subject (within limit)",
			subject:  strings.Repeat("a", 255),
			expected: true,
		},
		{
			name:     "valid mixed case subject",
			subject:  "UserName123",
			expected: true,
		},
		{
			name:     "valid subject with plus",
			subject:  "user+tag",
			expected: true,
		},
		{
			name:     "valid subject with equals",
			subject:  "user=value",
			expected: true,
		},

		// Real-world OIDC provider examples
		// Google OIDC: https://developers.google.com/identity/openid-connect/openid-connect
		{
			name:     "Google subject identifier",
			subject:  "10769150350006150715113082367",
			expected: true,
		},
		// GitHub Actions OIDC: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
		{
			name:     "GitHub Actions subject - repo ref",
			subject:  "repo:octo-org/octo-repo:ref:refs/heads/main",
			expected: true,
		},
		// Okta OIDC: https://developer.okta.com/docs/reference/api/oidc/
		{
			name:     "Okta subject identifier - with pipe",
			subject:  "okta|00uhzsq8pw5e6bWGe0h7",
			expected: true,
		},
		// OIDC Core 1.0 Specification: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
		{
			name:     "OIDC spec example - numeric",
			subject:  "24400320",
			expected: true,
		},
		{
			name:     "OIDC spec example - alphanumeric",
			subject:  "AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4",
			expected: true,
		},

		// Invalid subjects - OIDC violations
		{
			name:     "empty subject (OIDC violation)",
			subject:  "",
			expected: false,
		},
		{
			name:     "subject too long (>255 chars)",
			subject:  strings.Repeat("a", 256),
			expected: false,
		},

		// Invalid subjects - whitespace and control characters
		{
			name:     "subject with space",
			subject:  "user 123",
			expected: false,
		},
		{
			name:     "subject with tab",
			subject:  "user\t123",
			expected: false,
		},
		{
			name:     "subject with newline",
			subject:  "user123\n",
			expected: false,
		},
		{
			name:     "subject with carriage return",
			subject:  "user123\r",
			expected: false,
		},
		{
			name:     "subject with null byte",
			subject:  "user\x00123",
			expected: false,
		},

		// Invalid subjects - injection risks
		{
			name:     "subject with single quote",
			subject:  "user'123",
			expected: false,
		},
		{
			name:     "subject with double quote",
			subject:  "user\"123",
			expected: false,
		},
		{
			name:     "subject with script tags",
			subject:  "user<script>alert(1)</script>",
			expected: false,
		},
		{
			name:     "subject with brackets",
			subject:  "user[123]",
			expected: false,
		},
		{
			name:     "subject with braces",
			subject:  "user{123}",
			expected: false,
		},
		{
			name:     "subject with semicolon",
			subject:  "user;123",
			expected: false,
		},

		// Edge cases
		{
			name:     "subject with Unicode",
			subject:  "用户123",
			expected: true,
		},
		{
			name:     "subject with emoji",
			subject:  "user😀123",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidSubject(tt.subject)
			if result != tt.expected {
				t.Errorf("IsValidSubject(%q) = %v, expected %v", tt.subject, result, tt.expected)
			}
		})
	}
}

func TestIsValidAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience string
		expected bool
	}{
		{
			name:     "valid audience",
			audience: "service123",
			expected: true,
		},
		{
			name:     "valid audience with hyphen",
			audience: "service-123",
			expected: true,
		},
		{
			name:     "valid audience with underscore",
			audience: "service_123",
			expected: true,
		},
		{
			name:     "valid audience with dot",
			audience: "service.123",
			expected: true,
		},
		{
			name:     "valid audience with colon",
			audience: "service:123",
			expected: true,
		},
		{
			name:     "valid audience with slash",
			audience: "service/path",
			expected: true,
		},
		{
			name:     "empty audience",
			audience: "",
			expected: false,
		},
		{
			name:     "audience too long",
			audience: string(make([]byte, 200)),
			expected: false,
		},
		{
			name:     "audience with space",
			audience: "service 123",
			expected: false,
		},
		{
			name:     "audience with newline",
			audience: "service123\n",
			expected: false,
		},
		{
			name:     "audience with special characters",
			audience: "service<script>",
			expected: false,
		},
		{
			name:     "audience with at sign",
			audience: "service@domain",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidAudience(tt.audience)
			if result != tt.expected {
				t.Errorf("IsValidAudience(%q) = %v, expected %v", tt.audience, result, tt.expected)
			}
		})
	}
}
