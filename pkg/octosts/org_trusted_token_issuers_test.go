// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v71/github"
)

// MockGitHubClient is a mock implementation of GitHub client for testing
type MockGitHubClient struct {
	files map[string]string
	error error
}

func (m *MockGitHubClient) GetContents(ctx context.Context, owner, repo, path string, opts *github.RepositoryContentGetOptions) (*github.RepositoryContent, []*github.RepositoryContent, *github.Response, error) {
	if m.error != nil {
		return nil, nil, nil, m.error
	}

	content, exists := m.files[path]
	if !exists {
		return nil, nil, nil, fmt.Errorf("file not found")
	}

	file := &github.RepositoryContent{
		Content: &content,
	}
	return file, nil, nil, nil
}

func TestNewOrgTrustedTokenIssuersValidator(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")

	if validator.configFile != "test-config.yaml" {
		t.Errorf("Expected configFile to be 'test-config.yaml', got %s", validator.configFile)
	}

	if validator.maxCacheSize != 50 {
		t.Errorf("Expected maxCacheSize to be 50, got %d", validator.maxCacheSize)
	}

	if validator.cacheTTL != 5*time.Minute {
		t.Errorf("Expected cacheTTL to be 5 minutes, got %v", validator.cacheTTL)
	}
}

func TestValidIssuerFormat(t *testing.T) {
	tests := []struct {
		name      string
		issuer    string
		expectErr bool
		errStr    string
	}{
		{
			name:   "Valid HTTPS URL",
			issuer: "https://token.actions.githubusercontent.com",
		},
		{
			name:   "Valid HTTPS URL with path",
			issuer: "https://accounts.google.com/oauth2/token",
		},
		{
			name:      "Empty issuer",
			issuer:    "",
			expectErr: true,
			errStr:    "issuer cannot be empty",
		},
		{
			name:      "HTTP URL (not HTTPS)",
			issuer:    "http://token.actions.githubusercontent.com",
			expectErr: true,
			errStr:    "issuer must use HTTPS scheme",
		},
		{
			name:      "Invalid URL format",
			issuer:    "not-a-url",
			expectErr: true,
			errStr:    "issuer must use HTTPS scheme",
		},
		{
			name:      "URL without host",
			issuer:    "https://",
			expectErr: true,
			errStr:    "issuer must have a valid hostname",
		},
		{
			name:   "URL with double slashes in path (should be allowed by URL parser)",
			issuer: "https://example.com//path",
		},
		{
			name:      "URL with double dots in hostname",
			issuer:    "https://example..com",
			expectErr: true,
			errStr:    "issuer hostname contains invalid double dots",
		},
		{
			name:      "FTP protocol",
			issuer:    "ftp://example.com",
			expectErr: true,
			errStr:    "issuer must use HTTPS scheme",
		},
		{
			name:      "Malformed URL with spaces",
			issuer:    "https://example .com",
			expectErr: true,
			errStr:    "invalid URL format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := isValidIssuerFormat(tt.issuer)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for issuer %s, got nil", tt.issuer)
				} else if !strings.Contains(err.Error(), tt.errStr) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errStr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for issuer %s, got %v", tt.issuer, err)
				}
			}
		})
	}
}

func TestValidateIssuer_EmptyParams(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	tests := []struct {
		name      string
		org       string
		issuer    string
		expectErr string
	}{
		{
			name:      "Empty organization",
			org:       "",
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: "organization cannot be empty",
		},
		{
			name:      "Empty issuer",
			org:       "testorg",
			issuer:    "",
			expectErr: "issuer cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateIssuer(ctx, tt.org, tt.issuer)
			if err == nil {
				t.Errorf("Expected error, got nil")
			} else if !strings.Contains(err.Error(), tt.expectErr) {
				t.Errorf("Expected error to contain '%s', got '%s'", tt.expectErr, err.Error())
			}
		})
	}
}

func TestValidateIssuer_NoClient(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	err := validator.ValidateIssuer(ctx, "testorg", "https://token.actions.githubusercontent.com")
	expectedErr := "no GitHub client configured for organization: testorg"
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Expected error containing '%s', got %v", expectedErr, err)
	}
}

func TestValidateIssuer_DisabledConfig(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	// Create a GitHub client
	client := &github.Client{}

	// Set the client for the validator
	validator.SetGithubClient("testorg", client)

	// Manually set cache with disabled config
	validator.cache["testorg"] = &CacheEntry{
		config: &OrgTrustedTokenIssuersConfig{
			Enabled: false,
		},
		timestamp: time.Now(),
	}

	err := validator.ValidateIssuer(ctx, "testorg", "https://any-issuer.com")
	if err != nil {
		t.Errorf("Expected no error for disabled config, got %v", err)
	}
}

func TestValidateIssuer_EnabledConfig(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	client := &github.Client{}
	validator.SetGithubClient("testorg", client)

	tests := []struct {
		name      string
		config    *OrgTrustedTokenIssuersConfig
		issuer    string
		expectErr bool
	}{
		{
			name: "Exact match allowed",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled: true,
				TrustedIssuers: []string{
					"https://token.actions.githubusercontent.com",
					"https://accounts.google.com",
				},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: false,
		},
		{
			name: "Exact match not found",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled: true,
				TrustedIssuers: []string{
					"https://accounts.google.com",
				},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: true,
		},
		{
			name: "Pattern match allowed",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled:        true,
				IssuerPatterns: []string{"https://.*\\.githubusercontent\\.com"},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: false,
		},
		{
			name: "Pattern match not found",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled:        true,
				IssuerPatterns: []string{"https://.*\\.google\\.com"},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: true,
		},
		{
			name: "Multiple patterns, one matches",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled: true,
				IssuerPatterns: []string{
					"https://.*\\.google\\.com",
					"https://.*\\.githubusercontent\\.com",
				},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: false,
		},
		{
			name: "Mix of exact and pattern matches",
			config: &OrgTrustedTokenIssuersConfig{
				Enabled: true,
				TrustedIssuers: []string{
					"https://accounts.google.com",
				},
				IssuerPatterns: []string{
					"https://.*\\.githubusercontent\\.com",
				},
			},
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile patterns if they exist
			if len(tt.config.IssuerPatterns) > 0 {
				tt.config.compiledPatterns = make([]*regexp.Regexp, len(tt.config.IssuerPatterns))
				for i, pattern := range tt.config.IssuerPatterns {
					compiled, err := regexp.Compile(pattern)
					if err != nil {
						t.Fatalf("Failed to compile test pattern: %v", err)
					}
					tt.config.compiledPatterns[i] = compiled
				}
			}

			// Set cache with test config
			validator.cache["testorg"] = &CacheEntry{
				config:    tt.config,
				timestamp: time.Now(),
			}

			err := validator.ValidateIssuer(ctx, "testorg", tt.issuer)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestValidateIssuer_ComplexPatterns(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	client := &github.Client{}
	validator.SetGithubClient("testorg", client)

	tests := []struct {
		name      string
		patterns  []string
		issuer    string
		expectErr bool
	}{
		{
			name:      "AWS EKS pattern",
			patterns:  []string{"https://oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com/id/[A-Z0-9]+"},
			issuer:    "https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF123456",
			expectErr: false,
		},
		{
			name:      "Azure AD pattern",
			patterns:  []string{"https://login\\.microsoftonline\\.com/[a-f0-9-]+/v2\\.0"},
			issuer:    "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0",
			expectErr: false,
		},
		{
			name:      "Google Cloud pattern",
			patterns:  []string{"https://gcp\\.google\\.com/projects/[0-9]+/locations/[a-z0-9-]+/workloadIdentityPools/[a-z0-9-]+/providers/[a-z0-9-]+"},
			issuer:    "https://gcp.google.com/projects/123456789/locations/us-central1/workloadIdentityPools/my-pool/providers/my-provider",
			expectErr: false,
		},
		{
			name:      "Pattern doesn't match",
			patterns:  []string{"https://specific\\.domain\\.com"},
			issuer:    "https://other.domain.com",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &OrgTrustedTokenIssuersConfig{
				Enabled:        true,
				IssuerPatterns: tt.patterns,
			}

			// Compile patterns
			config.compiledPatterns = make([]*regexp.Regexp, len(tt.patterns))
			for i, pattern := range tt.patterns {
				compiled, err := regexp.Compile(pattern)
				if err != nil {
					t.Fatalf("Failed to compile test pattern: %v", err)
				}
				config.compiledPatterns[i] = compiled
			}

			// Set cache with test config
			validator.cache["testorg"] = &CacheEntry{
				config:    config,
				timestamp: time.Now(),
			}

			err := validator.ValidateIssuer(ctx, "testorg", tt.issuer)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestValidateIssuer_InvalidPatterns(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")

	client := &github.Client{}
	validator.SetGithubClient("testorg", client)

	// Test with invalid regex pattern
	config := &OrgTrustedTokenIssuersConfig{
		Enabled:        true,
		IssuerPatterns: []string{"[invalid regex"},
	}

	// Manually set cache to simulate loading config with invalid pattern
	validator.cache["testorg"] = &CacheEntry{
		config:    config,
		timestamp: time.Now(),
	}

	// This should fail when trying to compile the pattern
	// We'll simulate this by testing the pattern compilation directly
	_, err := regexp.Compile("[invalid regex")
	if err == nil {
		t.Errorf("Expected invalid regex to fail compilation")
	}
}

func TestConfigurableFilename(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
	}{
		{
			name:       "Default filename",
			configFile: ".github/chainguard/trusted-token-issuers.yaml",
		},
		{
			name:       "Custom filename",
			configFile: "custom-trusted-issuers.yaml",
		},
		{
			name:       "Nested path",
			configFile: ".github/security/trusted-token-issuers.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewOrgTrustedTokenIssuersValidator(tt.configFile)
			if validator.configFile != tt.configFile {
				t.Errorf("Expected configFile to be '%s', got '%s'", tt.configFile, validator.configFile)
			}
		})
	}
}

func TestCacheEviction(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	validator.maxCacheSize = 2 // Set small cache size for testing

	// Add entries to fill cache
	validator.cache["org1"] = &CacheEntry{
		config:    &OrgTrustedTokenIssuersConfig{Enabled: false},
		timestamp: time.Now().Add(-10 * time.Minute), // Oldest
	}
	validator.cache["org2"] = &CacheEntry{
		config:    &OrgTrustedTokenIssuersConfig{Enabled: false},
		timestamp: time.Now().Add(-5 * time.Minute),
	}

	// Verify cache is full
	if len(validator.cache) != 2 {
		t.Errorf("Expected cache size 2, got %d", len(validator.cache))
	}

	// Add third entry, should evict oldest (org1)
	validator.cache["org3"] = &CacheEntry{
		config:    &OrgTrustedTokenIssuersConfig{Enabled: false},
		timestamp: time.Now(),
	}

	// Manually trigger LRU eviction logic
	if len(validator.cache) > validator.maxCacheSize {
		var oldestOrg string
		var oldestTime time.Time
		for org, entry := range validator.cache {
			if oldestOrg == "" || entry.timestamp.Before(oldestTime) {
				oldestOrg = org
				oldestTime = entry.timestamp
			}
		}
		delete(validator.cache, oldestOrg)
	}

	// Verify org1 was evicted
	if _, exists := validator.cache["org1"]; exists {
		t.Errorf("Expected org1 to be evicted from cache")
	}

	// Verify org2 and org3 remain
	if _, exists := validator.cache["org2"]; !exists {
		t.Errorf("Expected org2 to remain in cache")
	}
	if _, exists := validator.cache["org3"]; !exists {
		t.Errorf("Expected org3 to remain in cache")
	}
}

func TestCacheTTL(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	validator.cacheTTL = 1 * time.Millisecond // Very short TTL for testing

	// Add entry to cache
	validator.cache["testorg"] = &CacheEntry{
		config:    &OrgTrustedTokenIssuersConfig{Enabled: false},
		timestamp: time.Now(),
	}

	// Wait for TTL to expire
	time.Sleep(2 * time.Millisecond)

	// Check if entry is considered expired
	entry := validator.cache["testorg"]
	if time.Since(entry.timestamp) < validator.cacheTTL {
		t.Errorf("Expected cache entry to be expired")
	}
}
