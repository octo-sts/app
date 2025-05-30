// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"strings"
	"testing"

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

	if validator.githubClients == nil {
		t.Errorf("Expected githubClients to be initialized")
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

func TestParseConfig(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")

	tests := []struct {
		name        string
		content     string
		expectErr   bool
		expectEmpty bool
	}{
		{
			name: "Valid config",
			content: `
enabled: true
trusted_issuers:
  - "https://token.actions.githubusercontent.com"
issuer_patterns:
  - "https://.*\\.github.*\\.com"
`,
			expectErr:   false,
			expectEmpty: false,
		},
		{
			name: "Disabled config",
			content: `
enabled: false
`,
			expectErr:   false,
			expectEmpty: false,
		},
		{
			name: "Invalid issuer",
			content: `
enabled: true
trusted_issuers:
  - "http://insecure.com"
`,
			expectErr:   true,
			expectEmpty: false,
		},
		{
			name: "Invalid regex pattern",
			content: `
enabled: true
issuer_patterns:
  - "[invalid regex"
`,
			expectErr:   true,
			expectEmpty: false,
		},
		{
			name:        "Invalid YAML",
			content:     `enabled: true\ninvalid yaml: [`,
			expectErr:   true,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := validator.parseConfig(tt.content)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if config == nil {
					t.Errorf("Expected config, got nil")
				}
			}
		})
	}
}

func TestValidateIssuer_ComplexPatterns(t *testing.T) {
	// Clear cache to avoid interference
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	tests := []struct {
		name      string
		content   string
		issuer    string
		expectErr bool
	}{
		{
			name: "AWS EKS pattern",
			content: `
enabled: true
issuer_patterns:
  - "https://oidc\\.eks\\.[a-z0-9-]+\\.amazonaws\\.com/id/[A-Z0-9]+"
`,
			issuer:    "https://oidc.eks.us-west-2.amazonaws.com/id/ABCDEF123456",
			expectErr: false,
		},
		{
			name: "Azure AD pattern",
			content: `
enabled: true
issuer_patterns:
  - "https://login\\.microsoftonline\\.com/[a-f0-9-]+/v2\\.0"
`,
			issuer:    "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0",
			expectErr: false,
		},
		{
			name: "Exact match",
			content: `
enabled: true
trusted_issuers:
  - "https://token.actions.githubusercontent.com"
`,
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: false,
		},
		{
			name: "No match",
			content: `
enabled: true
trusted_issuers:
  - "https://other.com"
`,
			issuer:    "https://token.actions.githubusercontent.com",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear cache for this test
			trustedTokenIssuers.Purge()

			// Create a mock client
			mockClient := &github.Client{}
			validator.SetGithubClient("testorg", mockClient)

			// Add the config content to cache directly
			trustedTokenIssuers.Add("testorg", tt.content)

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

func TestValidateIssuer_InvalidPatterns(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")

	// Test with invalid regex pattern
	invalidContent := `
enabled: true
issuer_patterns:
  - "[invalid regex"
`

	// This should fail when trying to parse the configuration
	_, err := validator.parseConfig(invalidContent)
	if err == nil {
		t.Errorf("Expected error for invalid regex pattern, got nil")
	}
}

func TestSharedCacheUsage(t *testing.T) {
	// Clear cache to start fresh
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator("test-config.yaml")
	ctx := context.Background()

	// Create a mock client
	mockClient := &github.Client{}
	validator.SetGithubClient("testorg", mockClient)

	configContent := `
enabled: true
trusted_issuers:
  - "https://token.actions.githubusercontent.com"
`

	// Add config to shared cache
	trustedTokenIssuers.Add("testorg", configContent)

	// First call should use cache
	err1 := validator.ValidateIssuer(ctx, "testorg", "https://token.actions.githubusercontent.com")
	if err1 != nil {
		t.Errorf("Expected no error on first call, got %v", err1)
	}

	// Second call should also use cache (no additional GitHub API call)
	err2 := validator.ValidateIssuer(ctx, "testorg", "https://token.actions.githubusercontent.com")
	if err2 != nil {
		t.Errorf("Expected no error on second call, got %v", err2)
	}

	// Verify cache contains the entry
	if _, ok := trustedTokenIssuers.Get("testorg"); !ok {
		t.Errorf("Expected cache to contain entry for testorg")
	}
}
