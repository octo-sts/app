// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"

	"github.com/octo-sts/app/pkg/oidcvalidate"
	"sigs.k8s.io/yaml"
)

// Mode selects how an org's trusted-issuer allowlist is applied.
type Mode string

const (
	// ModeEnforce rejects tokens whose issuer is not permitted. Default.
	ModeEnforce Mode = "enforce"
	// ModeAudit permits them and records what would have been rejected.
	ModeAudit Mode = "audit"
)

// Size caps bound memory and compile time; RE2 cannot backtrack catastrophically.
const (
	maxIssuers        = 64
	maxIssuerPatterns = 16
	maxPatternLen     = 256
)

// OrgTrustedIssuers is an org-wide allowlist of OIDC issuers read from
// OrgTrustedIssuersPath; when present, only issuers it permits may federate.
type OrgTrustedIssuers struct {
	Mode Mode `json:"mode,omitempty" jsonschema:"enum=enforce,enum=audit"`

	// Issuers is matched byte-exactly.
	Issuers []string `json:"issuers,omitempty"`

	// IssuerPatterns are anchored regexps matching the entire issuer URL.
	IssuerPatterns []string `json:"issuer_patterns,omitempty"`
}

// ParseOrgTrustedIssuers unmarshals and compiles raw file contents. Both the
// exchange path and the webhook check call this, so they cannot disagree.
func ParseOrgTrustedIssuers(raw []byte) (*IssuerAllowlist, error) {
	var cfg OrgTrustedIssuers
	if err := yaml.UnmarshalStrict(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parsing organization trusted issuers: %w", err)
	}
	return cfg.Compile()
}

// IssuerAllowlist is a compiled OrgTrustedIssuers, immutable and concurrent-safe.
type IssuerAllowlist struct {
	mode     Mode
	issuers  []string
	patterns []*regexp.Regexp
}

// Compile validates the configuration and prepares it for matching. Unlike
// TrustPolicy.Compile it returns a NEW value, so a cached allowlist cannot be
// invalidated by a concurrent recompile.
func (c *OrgTrustedIssuers) Compile() (*IssuerAllowlist, error) {
	mode := c.Mode
	switch mode {
	case "":
		mode = ModeEnforce
	case ModeEnforce, ModeAudit:
	default:
		return nil, fmt.Errorf("unknown mode %q (want %q or %q)", c.Mode, ModeEnforce, ModeAudit)
	}

	// An empty file would deny all federation in the org: a silent outage.
	if len(c.Issuers) == 0 && len(c.IssuerPatterns) == 0 {
		return nil, errors.New("must list at least one entry in issuers or issuer_patterns")
	}

	if len(c.Issuers) > maxIssuers {
		return nil, fmt.Errorf("too many issuers: %d (max %d)", len(c.Issuers), maxIssuers)
	}
	if len(c.IssuerPatterns) > maxIssuerPatterns {
		return nil, fmt.Errorf("too many issuer_patterns: %d (max %d)", len(c.IssuerPatterns), maxIssuerPatterns)
	}

	for _, iss := range c.Issuers {
		if !oidcvalidate.IsValidIssuer(iss) {
			return nil, fmt.Errorf("invalid issuer %q", iss)
		}
		if err := checkLowercaseSchemeAndHost(iss); err != nil {
			return nil, err
		}
	}

	patterns := make([]*regexp.Regexp, 0, len(c.IssuerPatterns))
	for i, p := range c.IssuerPatterns {
		if len(p) > maxPatternLen {
			return nil, fmt.Errorf("issuer_patterns[%d] too long: %d chars (max %d)", i, len(p), maxPatternLen)
		}
		if err := checkPatternCannotSpanHost(i, p); err != nil {
			return nil, err
		}
		// Compile p ALONE first: the group below hides an unbalanced ")", so
		// "token\.example\.com)|(" wraps to "^(?:token\.example\.com)|()$", whose "()$"
		// alternative matches everything. A legitimate top-level "a|b" still compiles.
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("invalid issuer_pattern %q: %w", p, err)
		}
		// Non-capturing group required: "|" binds looser than the anchors, so
		// "^"+p+"$" parses as "(^A)|(B$)", leaving an alternation unanchored.
		re, err := regexp.Compile("^(?:" + p + ")$")
		if err != nil {
			return nil, fmt.Errorf("invalid issuer_pattern %q: %w", p, err)
		}
		patterns = append(patterns, re)
	}

	return &IssuerAllowlist{
		mode:     mode,
		issuers:  slices.Clone(c.Issuers),
		patterns: patterns,
	}, nil
}

func (a *IssuerAllowlist) Mode() Mode { return a.mode }

// Allows reports whether issuer is permitted. The two lists are a union, deliberately
// unlike TrustPolicy where they are mutually exclusive. Patterns honour inline flags
// such as (?i), so matching is only as strict as the pattern.
func (a *IssuerAllowlist) Allows(issuer string) bool {
	if slices.Contains(a.issuers, issuer) {
		return true
	}
	for _, re := range a.patterns {
		if re.MatchString(issuer) {
			return true
		}
	}
	return false
}

// checkPatternCannotSpanHost rejects an issuer_pattern that can match "/" and so span
// past the host: "https://.*\.example\.com" also permits "https://evil.com/x.example.com".
// BEST-EFFORT FOOTGUN GUARD, NOT A SECURITY BOUNDARY — the author is the org owner.
//
// It inspects the regexp/syntax AST — the same parse regexp.Compile performs — so it
// cannot disagree with the matcher about tokenization. A hand-written byte scanner did
// this before and disagreed six times, each a bypass.
func checkPatternCannotSpanHost(i int, p string) error {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		// Unparseable: the compile below reports it better than we would.
		return nil
	}
	if what := spanningElement(re, false); what != "" {
		return fmt.Errorf(`issuer_patterns[%d]: %s, so the pattern can span past the `+
			`host into an attacker-controlled domain, as "https://.*\.example\.com" also `+
			`permits "https://totally-evil.com/x.example.com" — escape literal dots as `+
			`"\." and bound each varying part, e.g. https://[a-z0-9-]+\.example\.com. Keep `+
			`"/" at a fixed position, writing a path one segment at a time, and give `+
			`alternatives their own issuer_patterns entries. This is a best-effort check, `+
			`not a guarantee: write patterns as narrowly as you can`, i, what)
	}
	return nil
}

// spanningElement describes the first element that lets the pattern match "/", or "".
//
// A class or "." matching "/" is rejected ANYWHERE: parsing desugars "\S", "[^\n]",
// "[[:ascii:]]", "\p{P}" and "[.-9]" into rune ranges, so one range test covers every
// spelling. A literal "/" is rejected only under a repetition, optional or alternation
// — at a fixed position it is how real multi-segment issuers are written, e.g.
// https://host\.example\.com/id/[A-Z0-9]+. variable carries that down the subtree.
func spanningElement(re *syntax.Regexp, variable bool) string {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpAlternate:
		variable = true
	}

	switch re.Op {
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return `"." can match "/"`

	case syntax.OpCharClass:
		for j := 0; j+1 < len(re.Rune); j += 2 {
			if re.Rune[j] <= '/' && '/' <= re.Rune[j+1] {
				return `a character class can match "/"`
			}
		}

	case syntax.OpLiteral:
		if variable && slices.Contains(re.Rune, '/') {
			return `a literal "/" sits inside a repetition, optional or alternation`
		}
	}

	for _, sub := range re.Sub {
		if what := spanningElement(sub, variable); what != "" {
			return what
		}
	}
	return ""
}

// checkLowercaseSchemeAndHost rejects uppercase in an issuer's scheme or host: matching
// is byte-exact, so those never match a real "iss" claim — a silent org-wide outage in
// enforce mode. It inspects the RAW string because url.Parse lowercases the scheme.
// Paths are legitimately mixed-case (e.g. AWS EKS /id/ABCDEF123456) and excluded.
func checkLowercaseSchemeAndHost(iss string) error {
	schemeAndHost := iss
	if i := strings.Index(iss, "://"); i >= 0 {
		if j := strings.Index(iss[i+3:], "/"); j >= 0 {
			schemeAndHost = iss[:i+3+j]
		}
	}
	if schemeAndHost != strings.ToLower(schemeAndHost) {
		return fmt.Errorf("issuer %q must be lowercase in scheme and host", iss)
	}
	return nil
}
