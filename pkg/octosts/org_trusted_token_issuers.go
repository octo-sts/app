// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v71/github"
	"gopkg.in/yaml.v3"
)

// OrgTrustedTokenIssuersConfig represents the organization-wide trusted token issuers configuration
type OrgTrustedTokenIssuersConfig struct {
	Description      string   `yaml:"description,omitempty"`
	Enabled          bool     `yaml:"enabled"`
	TrustedIssuers   []string `yaml:"trusted_issuers,omitempty"`
	IssuerPatterns   []string `yaml:"issuer_patterns,omitempty"`
	compiledPatterns []*regexp.Regexp
}

// CacheEntry represents a cached configuration entry
type CacheEntry struct {
	config    *OrgTrustedTokenIssuersConfig
	timestamp time.Time
}

// OrgTrustedTokenIssuersValidator provides organization-wide trusted token issuer validation
type OrgTrustedTokenIssuersValidator struct {
	cache         map[string]*CacheEntry
	cacheMutex    sync.RWMutex
	maxCacheSize  int
	cacheTTL      time.Duration
	configFile    string
	githubClients map[string]*github.Client
}

// NewOrgTrustedTokenIssuersValidator creates a new validator instance
func NewOrgTrustedTokenIssuersValidator(configFile string) *OrgTrustedTokenIssuersValidator {
	return &OrgTrustedTokenIssuersValidator{
		cache:         make(map[string]*CacheEntry),
		maxCacheSize:  50,
		cacheTTL:      5 * time.Minute,
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
		return fmt.Errorf("issuer cannot be empty")
	}

	// Parse as URL
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
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
	// Check cache first
	v.cacheMutex.RLock()
	if entry, exists := v.cache[org]; exists {
		if time.Since(entry.timestamp) < v.cacheTTL {
			v.cacheMutex.RUnlock()
			return entry.config, nil
		}
	}
	v.cacheMutex.RUnlock()

	// Get GitHub client for this organization
	client, exists := v.githubClients[org]
	if !exists {
		return nil, fmt.Errorf("no GitHub client configured for organization: %s", org)
	}

	// Fetch file from GitHub
	file, _, _, err := client.Repositories.GetContents(ctx, org, ".github", v.configFile, nil)
	if err != nil {
		// If file doesn't exist, return empty config (disabled)
		return &OrgTrustedTokenIssuersConfig{Enabled: false}, nil
	}

	if file == nil {
		return &OrgTrustedTokenIssuersConfig{Enabled: false}, nil
	}

	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get file content: %v", err)
	}

	// Parse YAML
	var config OrgTrustedTokenIssuersConfig
	if err := yaml.Unmarshal([]byte(content), &config); err != nil {
		return nil, fmt.Errorf("failed to parse trusted token issuers config: %v", err)
	}

	// Validate issuer formats
	for _, issuer := range config.TrustedIssuers {
		if err := isValidIssuerFormat(issuer); err != nil {
			return nil, fmt.Errorf("invalid trusted issuer '%s': %v", issuer, err)
		}
	}

	// Compile regex patterns
	config.compiledPatterns = make([]*regexp.Regexp, len(config.IssuerPatterns))
	for i, pattern := range config.IssuerPatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid issuer pattern '%s': %v", pattern, err)
		}
		config.compiledPatterns[i] = compiled
	}

	// Update cache
	v.cacheMutex.Lock()
	// LRU eviction if cache is full
	if len(v.cache) >= v.maxCacheSize {
		var oldestOrg string
		var oldestTime time.Time
		for org, entry := range v.cache {
			if oldestOrg == "" || entry.timestamp.Before(oldestTime) {
				oldestOrg = org
				oldestTime = entry.timestamp
			}
		}
		delete(v.cache, oldestOrg)
	}

	v.cache[org] = &CacheEntry{
		config:    &config,
		timestamp: time.Now(),
	}
	v.cacheMutex.Unlock()

	return &config, nil
}

// ValidateIssuer validates if an issuer is trusted for the given organization
func (v *OrgTrustedTokenIssuersValidator) ValidateIssuer(ctx context.Context, org, issuer string) error {
	if org == "" {
		return fmt.Errorf("organization cannot be empty")
	}

	if issuer == "" {
		return fmt.Errorf("issuer cannot be empty")
	}

	// Load organization configuration
	config, err := v.loadOrgConfig(ctx, org)
	if err != nil {
		return fmt.Errorf("failed to load trusted token issuers config for org %s: %v", org, err)
	}

	// If not enabled, allow all issuers (backward compatibility)
	if !config.Enabled {
		return nil
	}

	// Check exact matches
	for _, trustedIssuer := range config.TrustedIssuers {
		if issuer == trustedIssuer {
			return nil
		}
	}

	// Check pattern matches
	for _, pattern := range config.compiledPatterns {
		if pattern.MatchString(issuer) {
			return nil
		}
	}

	return fmt.Errorf("issuer '%s' is not in the trusted token issuers list for organization '%s'", issuer, org)
}
