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
		// First, so a loose-and-malformed pattern reports its looseness.
		if err := checkNoSlashMatchingAtom(i, p); err != nil {
			return nil, err
		}
		if err := checkNoSeparatorUnderQuantifier(i, p); err != nil {
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

// checkNoSlashMatchingAtom rejects any single-character atom that can match "/": such an
// atom lets a pattern span past the host, so "https://.*\.example\.com" would also permit
// "https://totally-evil.com/x.example.com". BEST-EFFORT FOOTGUN GUARD, NOT A SECURITY
// BOUNDARY — the author is the org owner.
//
// The test is EMPIRICAL — each atom compiled alone as "^atom$" and asked whether it matches
// "/" — because banned spellings cannot be enumerated: "\S", "[^\n]" and "[[:ascii:]]" match
// "/" without containing ".", and "[.-9]" holds "/" by range. A LITERAL "/" stays allowed;
// unterminated brackets are left to regexp.Compile.
//
// Being per-ATOM it cannot see a "/" that only spans because of surrounding
// STRUCTURE; checkNoSeparatorUnderQuantifier covers that half.
func checkNoSlashMatchingAtom(i int, p string) error {
	for j := 0; j < len(p); j++ {
		var atom string

		switch p[j] {
		case '.':
			atom = "."

		case '\\':
			end := endOfEscape(p, j)
			if end < 0 {
				// Skip the escaped byte so "\." is never read as a wildcard.
				j++
				continue
			}
			atom, j = p[j:end], end-1

		case '[':
			end := endOfBracketExpression(p, j)
			if end < 0 {
				return nil
			}
			atom, j = p[j:end], end-1

		default:
			continue
		}

		re, err := regexp.Compile("^" + atom + "$")
		if err != nil {
			// Fail CLOSED: an atom we cannot analyze is not one we know is safe, and
			// skipping it would turn every scanner mis-parse into a silent bypass.
			return fmt.Errorf(`issuer_patterns[%d]: cannot verify that %q cannot `+
				`match "/" (%v), so the pattern is rejected rather than assumed `+
				`safe — rewrite it with a plain class such as [a-z0-9-]`, i, atom, err)
		}
		if re.MatchString("/") {
			return fmt.Errorf(`issuer_patterns[%d]: %q can match "/", so the pattern `+
				`can span past the host into an attacker-controlled domain, as `+
				`"https://.*\.example\.com" also permits `+
				`"https://totally-evil.com/x.example.com" — escape literal dots as `+
				`"\." and bound each varying part, e.g. `+
				`https://[a-z0-9-]+\.example\.com. Write a path one segment at a `+
				`time with literal separators, e.g. `+
				`https://example\.com/realms/[a-z0-9-]+, because a class that `+
				`itself contains "/" is rejected for the same reason. `+
				`This is a best-effort check, `+
				`not a guarantee: write patterns as narrowly as you can`, i, atom)
		}
	}
	return nil
}

// checkNoSeparatorUnderQuantifier rejects a pattern where a "/"-matching element sits
// inside a repetition, an optional, or an alternation. The per-atom scan cannot see
// this: every atom in "([a-z0-9.-]+/)*" is innocent on its own, yet the group spans
// separators, so "https://([a-z0-9.-]+/)*trusted\.example\.com" matches
// "https://evil.com/x/trusted.example.com" — attacker-chosen host, trusted name demoted
// to a path segment. "?", "{n,m}" and alternation do the same.
//
// A literal "/" at a FIXED position stays allowed, so real multi-segment issuers such as
// "https://host\.example\.com/id/[A-Z0-9]+" still validate. An author who wants
// alternatives writes separate issuer_patterns entries instead of one alternation.
func checkNoSeparatorUnderQuantifier(i int, p string) error {
	re, err := syntax.Parse(p, syntax.Perl)
	if err != nil {
		// Unparseable: regexp.Compile reports it better than we would.
		return nil
	}
	if found := separatorUnderQuantifier(re, false); found != "" {
		return fmt.Errorf(`issuer_patterns[%d]: %s can match "/" from inside a `+
			`repetition, optional or alternation, so the pattern can span past the `+
			`host — "https://([a-z0-9.-]+/)*trusted\.example\.com" also permits `+
			`"https://evil.com/x/trusted.example.com". Keep "/" at a fixed position, `+
			`e.g. https://host\.example\.com/id/[A-Z0-9]+, and write alternatives as `+
			`separate issuer_patterns entries rather than one alternation`, i, found)
	}
	return nil
}

// separatorUnderQuantifier reports the first "/"-matching element reachable under a
// variable-length or alternating node, or "" if there is none. variable becomes true
// once inside such a node and stays true for the whole subtree.
func separatorUnderQuantifier(re *syntax.Regexp, variable bool) string {
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat, syntax.OpAlternate:
		variable = true
	}
	if variable {
		if what := slashMatchingElement(re); what != "" {
			return what
		}
	}
	for _, sub := range re.Sub {
		if found := separatorUnderQuantifier(sub, variable); found != "" {
			return found
		}
	}
	return ""
}

// slashMatchingElement names re if it can match "/" on its own, else "".
func slashMatchingElement(re *syntax.Regexp) string {
	switch re.Op {
	case syntax.OpLiteral:
		if slices.Contains(re.Rune, '/') {
			return `a literal "/"`
		}
	case syntax.OpCharClass:
		for j := 0; j+1 < len(re.Rune); j += 2 {
			if re.Rune[j] <= '/' && '/' <= re.Rune[j+1] {
				return "a character class containing \"/\""
			}
		}
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return `"." (which matches "/")`
	}
	return ""
}

// endOfEscape returns the index just past the character-class escape starting at the
// backslash at p[j], or -1 when there is no atom to test (an escaped literal or
// trailing backslash) and the caller should skip two bytes.
func endOfEscape(p string, j int) int {
	if j+1 >= len(p) {
		return -1
	}
	switch p[j+1] {
	case 'd', 'D', 's', 'S', 'w', 'W':
		return j + 2

	// Numeric escapes SPELL characters rather than naming classes ("\x2F", "\x{2F}" and
	// "\057" are all "/"); as escaped literals they would be skipped and never tested.
	case 'x':
		if j+2 >= len(p) {
			return -1
		}
		if p[j+2] == '{' {
			if k := strings.IndexByte(p[j+2:], '}'); k >= 0 {
				return j + 2 + k + 1
			}
			return -1
		}
		if j+3 < len(p) && isHexDigit(p[j+2]) && isHexDigit(p[j+3]) {
			return j + 4
		}
		return -1
	case '0', '1', '2', '3', '4', '5', '6', '7':
		end := j + 2
		for end < len(p) && end < j+4 && p[end] >= '0' && p[end] <= '7' {
			end++
		}
		return end

	case 'p', 'P':
		if j+2 >= len(p) {
			return -1
		}
		if p[j+2] != '{' {
			return j + 3
		}
		if k := strings.IndexByte(p[j+2:], '}'); k >= 0 {
			return j + 2 + k + 1
		}
		return -1
	default:
		return -1
	}
}

func isHexDigit(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// endOfBracketExpression returns the index just past the bracket expression opening at
// p[j], or -1 if unterminated. More than a search for "]": a backslash escapes the next
// byte ("[a-z\]]"), a POSIX class carries its own "]" ("[[:alpha:]]"), and a leading "]"
// is a literal member ("[^]]").
func endOfBracketExpression(p string, j int) int {
	k := j + 1
	if k < len(p) && p[k] == '^' {
		k++
	}
	// RE2 reads a first-position "]" as a literal; stopping there would extract the
	// uncompilable "[^]" and leave the real class untested.
	if k < len(p) && p[k] == ']' {
		k++
	}
	for ; k < len(p); k++ {
		switch p[k] {
		case '\\':
			k++
		case '[':
			// "[:name:]" is a POSIX class only when a ":]" actually follows; otherwise
			// RE2 reads this "[" as an ordinary member and the real "]" is still ahead,
			// so keep scanning: bailing out let "[[:/-~]", holding "/", pass untested.
			if strings.HasPrefix(p[k:], "[:") {
				if end := strings.Index(p[k:], ":]"); end >= 0 {
					k += end + 1
				}
			}
		case ']':
			return k + 1
		}
	}
	return -1
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
