// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package oidcvalidate

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// controlCharsAndWhitespace contains ASCII control characters (0x00-0x1f) plus whitespace
	controlCharsAndWhitespace = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f \t\n\r"
)

// IsValidIssuer validates an OIDC issuer according to RFC 8414 and OpenID Connect Core 1.0:
// - Must use HTTPS scheme (except localhost for testing)
// - Must be a valid URL without query string or fragment
// - Must not end with a slash
// - Must have a valid hostname
// - Length constraints for security
func IsValidIssuer(iss string) bool {
	// Basic length check
	if len(iss) == 0 || utf8.RuneCountInString(iss) > 255 {
		return false
	}

	// Parse as URL
	parsedURL, err := url.Parse(iss)
	if err != nil {
		return false
	}

	// Must use HTTPS (allow HTTP only for localhost/127.0.0.1 for development/testing environments)
	if parsedURL.Scheme != "https" {
		if parsedURL.Scheme == "http" {
			host := parsedURL.Hostname()
			if host != "localhost" && host != "127.0.0.1" && host != "::1" {
				return false
			}
		} else {
			// Reject any scheme that is not HTTPS or HTTP
			return false
		}
	}

	// Must not contain query string or fragment (RFC 8414)
	// Check both parsed components and raw string for fragments/queries
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return false
	}
	if strings.ContainsAny(iss, "?#") {
		return false
	}

	// Must have a valid hostname
	if parsedURL.Host == "" {
		return false
	}

	// Reject URLs with userinfo (user:pass@host)
	if parsedURL.User != nil {
		return false
	}

	// Comprehensive hostname validation
	if !isValidHostname(parsedURL.Hostname()) {
		return false
	}

	// Path validation - if present, must be valid
	if parsedURL.Path != "" {
		// Reject paths with .. or other suspicious patterns
		if strings.Contains(parsedURL.Path, "..") {
			return false
		}
		// Must start with / if path is present
		if !strings.HasPrefix(parsedURL.Path, "/") {
			return false
		}
		// Reject multiple consecutive slashes (e.g., //, ///)
		if strings.Contains(parsedURL.Path, "//") {
			return false
		}
		// Reject multiple consecutive tildes (e.g., ~~, ~~~)
		if strings.Contains(parsedURL.Path, "~~") {
			return false
		}
		// Reject paths ending with tilde (could indicate backup files)
		if strings.HasSuffix(parsedURL.Path, "~") {
			return false
		}
		// Strict path character validation - only allow safe characters
		// Allow: letters, digits, hyphens, dots, underscores, tildes, forward slashes
		pathRe := regexp.MustCompile(`^[a-zA-Z0-9\-._~/]+$`)
		if !pathRe.MatchString(parsedURL.Path) {
			return false
		}
		// Additional validation: each path segment should be reasonable
		segments := strings.Split(parsedURL.Path, "/")
		for _, segment := range segments {
			if segment == "" {
				continue // Skip empty segments (like the first one after leading /)
			}
			// Reject segments that are just dots or tildes
			if segment == "." || segment == ".." || segment == "~" {
				return false
			}
			// Reject very long path segments to prevent buffer overflows, path traversal,
			// and resource exhaustion. RFC 3986 sets no explicit limit, but a 150-character
			// cap is reasonable for legitimate paths in most apps.
			if len(segment) > 150 {
				return false
			}
		}
	}

	return true
}

// IsValidSubject validates a subject identifier according to OpenID Connect Core 1.0:
// - Must not be empty (REQUIRED)
// - Must be a string with maximum length of 255 ASCII characters
// - Must not contain whitespace or control characters
// - Case sensitive string comparison
func IsValidSubject(sub string) bool {
	// Must not be empty (OIDC Core requirement)
	if sub == "" {
		return false
	}

	// Length validation - OIDC recommends max 255 ASCII characters
	if utf8.RuneCountInString(sub) > 255 {
		return false
	}

	// Must not contain control characters, whitespace, or newlines
	// These could interfere with logging, storage, or protocol handling
	if strings.ContainsAny(sub, controlCharsAndWhitespace) {
		return false
	}

	// Reject obviously problematic characters that could cause issues
	// in various contexts (JSON, XML, SQL, shell, etc.)
	// Allow: | : / @ - (commonly used by Auth0, GitHub Actions, etc.)
	if strings.ContainsAny(sub, "\"'`\\<>;&$(){}[]") {
		return false
	}

	// The subject MUST be valid UTF-8 (already ensured by Go string type)
	// and should be printable characters only
	for _, r := range sub {
		// Reject non-printable characters (except those already caught above)
		if !unicode.IsPrint(r) {
			return false
		}
	}

	return true
}

// IsValidAudience validates an audience identifier according to OpenID Connect Core 1.0:
// - Must not be empty (audience is REQUIRED)
// - Should be a URI or an arbitrary string that uniquely identifies the audience
// - Case sensitive string comparison
// - Maximum length of 255 characters for security
// - Must not contain control characters or injection-prone characters
func IsValidAudience(aud string) bool {
	// Must not be empty (OIDC requirement)
	if aud == "" {
		return false
	}

	// Length validation for security
	if utf8.RuneCountInString(aud) > 255 {
		return false
	}

	// Must not contain control characters, whitespace that could cause parsing issues
	if strings.ContainsAny(aud, controlCharsAndWhitespace) {
		return false
	}

	// Reject characters that could cause injection issues or confusion
	if strings.ContainsAny(aud, "\"'`\\<>;|&$(){}[]@") {
		return false
	}

	// Audience should be printable characters only
	for _, r := range aud {
		if !unicode.IsPrint(r) {
			return false
		}
	}

	return true
}

// isValidHostname validates hostnames against homograph attacks and Unicode confusion
func isValidHostname(hostname string) bool {
	// Empty hostname is invalid
	if hostname == "" {
		return false
	}

	// Reject control characters, whitespace, tabs, newlines
	if strings.ContainsAny(hostname, controlCharsAndWhitespace) {
		return false
	}

	// Reject Unicode characters to prevent homograph attacks
	// Examples: exämple.com (ä), eⓍample.com (Ⓧ), еxample.com (Cyrillic е)
	for _, r := range hostname {
		if r > 127 {
			return false
		}
	}

	return true
}
