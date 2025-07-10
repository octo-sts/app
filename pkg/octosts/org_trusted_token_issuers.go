// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v72/github"
	"sigs.k8s.io/yaml"
)

// Error constants to reduce duplication
const (
	errOrgCannotBeEmpty    = "organization cannot be empty"
	errIssuerCannotBeEmpty = "issuer cannot be empty"
)

// OrgTrustedTokenIssuersConfig represents the organization-wide trusted token issuers configuration
type OrgTrustedTokenIssuersConfig struct {
	Description      string           `json:"description,omitempty"`
	Enabled          bool             `json:"enabled"`
	TrustedIssuers   []string         `json:"trusted_issuers,omitempty"`
	IssuerPatterns   []string         `json:"issuer_patterns,omitempty"`
	compiledPatterns []*regexp.Regexp `json:"-"`
}

// OrgTrustedTokenIssuersValidator provides organization-wide trusted token issuer validation
type OrgTrustedTokenIssuersValidator struct {
	configFile    string
	githubClients map[string]*github.Client
}

// NewOrgTrustedTokenIssuersValidator creates a new validator instance
func NewOrgTrustedTokenIssuersValidator(configFile string) *OrgTrustedTokenIssuersValidator {
	return &OrgTrustedTokenIssuersValidator{
		configFile:    configFile,
		githubClients: make(map[string]*github.Client),
	}
}

// SetGithubClient sets the GitHub client for a specific organization
func (v *OrgTrustedTokenIssuersValidator) SetGithubClient(org string, client *github.Client) {
	v.githubClients[org] = client
}

// isValidIssuerFormat validates the format of an issuer URL
func isValidIssuerFormat(issuer string) error {
	if issuer == "" {
		return fmt.Errorf(errIssuerCannotBeEmpty)
	}

	// Parse as URL
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Must be HTTPS
	if u.Scheme != "https" {
		return fmt.Errorf("issuer must use HTTPS scheme, got: %s", u.Scheme)
	}

	// Must have a host
	if u.Host == "" {
		return fmt.Errorf("issuer must have a valid hostname")
	}

	// Check for double dots in hostname
	if strings.Contains(u.Host, "..") {
		return fmt.Errorf("issuer hostname contains invalid double dots")
	}

	return nil
}

// loadOrgConfig loads the trusted token issuers configuration for an organization
func (v *OrgTrustedTokenIssuersValidator) loadOrgConfig(ctx context.Context, org string) (*OrgTrustedTokenIssuersConfig, error) {
	// Check cache first using the shared trustedTokenIssuers cache
	if cachedRaw, ok := trustedTokenIssuers.Get(org); ok {
		clog.InfoContextf(ctx, "found trusted token issuers in cache for %s", org)
		return v.parseConfig(cachedRaw)
	}

	// Get GitHub client for this organization
	client, exists := v.githubClients[org]
	if !exists {
		return nil, fmt.Errorf("no GitHub client configured for organization: %s", org)
	}

	// Fetch file from GitHub
	file, _, _, err := client.Repositories.GetContents(ctx,
		org, ".github", v.configFile,
		&github.RepositoryContentGetOptions{ /* defaults to the default branch */ },
	)
	if err != nil {
		// If file doesn't exist, return empty config (disabled)
		emptyConfig := &OrgTrustedTokenIssuersConfig{Enabled: false}
		return emptyConfig, nil
	}

	if file == nil {
		emptyConfig := &OrgTrustedTokenIssuersConfig{Enabled: false}
		return emptyConfig, nil
	}

	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %w", err)
	}

	// Add to cache
	if evicted := trustedTokenIssuers.Add(org, content); evicted {
		clog.InfoContextf(ctx, "evicted trusted token issuers cache key %s", org)
	}

	return v.parseConfig(content)
}

// parseConfig parses the raw YAML content into a configuration struct
func (v *OrgTrustedTokenIssuersValidator) parseConfig(content string) (*OrgTrustedTokenIssuersConfig, error) {
	// Parse YAML
	var config OrgTrustedTokenIssuersConfig
	if err := yaml.UnmarshalStrict([]byte(content), &config); err != nil {
		return nil, fmt.Errorf("failed to parse trusted token issuers config: %w", err)
	}

	// Validate configuration limits to prevent DoS and align with cache capacity
	// With 100 orgs in cache, these limits ensure reasonable memory usage:
	// 100 orgs × 25 issuers × ~100 bytes = ~250KB for issuer strings
	// 100 orgs × 5 patterns × compiled regex = manageable regex memory
	if len(config.TrustedIssuers) > 25 {
		return nil, fmt.Errorf("too many trusted issuers: maximum 25 allowed, got %d", len(config.TrustedIssuers))
	}
	if len(config.IssuerPatterns) > 5 {
		return nil, fmt.Errorf("too many issuer patterns: maximum 5 allowed, got %d", len(config.IssuerPatterns))
	}

	// Additional memory-based validation
	totalMemoryEstimate := 0
	for _, issuer := range config.TrustedIssuers {
		totalMemoryEstimate += len(issuer)
		if len(issuer) > 512 { // Prevent extremely long issuer URLs
			return nil, fmt.Errorf("issuer URL too long: maximum 512 characters, got %d", len(issuer))
		}
	}
	for _, pattern := range config.IssuerPatterns {
		totalMemoryEstimate += len(pattern)
		if len(pattern) > 256 { // Prevent extremely complex regex patterns  
			return nil, fmt.Errorf("issuer pattern too long: maximum 256 characters, got %d", len(pattern))
		}
	}
	
	// Limit total configuration memory to ~5KB per organization
	if totalMemoryEstimate > 5120 {
		return nil, fmt.Errorf("configuration too large: maximum 5KB per organization, got %d bytes", totalMemoryEstimate)
	}

	// Validate issuer formats
	for _, issuer := range config.TrustedIssuers {
		if err := isValidIssuerFormat(issuer); err != nil {
			return nil, fmt.Errorf("invalid trusted issuer '%s': %w", issuer, err)
		}
	}

	// Compile regex patterns with pre-allocated slice for better memory efficiency
	config.compiledPatterns = make([]*regexp.Regexp, 0, len(config.IssuerPatterns))
	for _, pattern := range config.IssuerPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer pattern '%s': %w", pattern, err)
		}
		config.compiledPatterns = append(config.compiledPatterns, compiled)
	}

	return &config, nil
}

// ValidateIssuer validates if an issuer is trusted for the given organization
func (v *OrgTrustedTokenIssuersValidator) ValidateIssuer(ctx context.Context, org, issuer string) error {
	if org == "" {
		return fmt.Errorf(errOrgCannotBeEmpty)
	}

	if issuer == "" {
		return fmt.Errorf(errIssuerCannotBeEmpty)
	}

	// Load organization configuration
	config, err := v.loadOrgConfig(ctx, org)
	if err != nil {
		return fmt.Errorf("failed to load trusted token issuers config for org %s: %w", org, err)
	}

	// If not enabled, allow all issuers (backward compatibility)
	if !config.Enabled {
		return nil
	}

	// Check exact matches using modern slices.Contains (Go 1.21+)
	if slices.Contains(config.TrustedIssuers, issuer) {
		return nil
	}

	// Check pattern matches
	for _, pattern := range config.compiledPatterns {
		if pattern.MatchString(issuer) {
			return nil
		}
	}

	return fmt.Errorf("issuer '%s' is not in the trusted token issuers list for organization '%s'", issuer, org)
}
