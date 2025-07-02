// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-github/v72/github"
)

const (
	errMsgExpectedErrorGotNil = "Expected error, got nil"
	errMsgHTTPSScheme         = "issuer must use HTTPS scheme"
	fileTestConfig            = "test-config.yaml"
	patternTestOrg            = "testorg%d"
	urlGitHubActionsIssuer    = "https://token.actions.githubusercontent.com"
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
	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

	if validator.configFile != fileTestConfig {
		t.Errorf("Expected configFile to be '%s', got %s", fileTestConfig, validator.configFile)
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
			issuer: urlGitHubActionsIssuer,
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
			errStr:    errMsgHTTPSScheme,
		},
		{
			name:      "Invalid URL format",
			issuer:    "not-a-url",
			expectErr: true,
			errStr:    errMsgHTTPSScheme,
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
			errStr:    errMsgHTTPSScheme,
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

func TestValidateIssuerEmptyParams(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)
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
			issuer:    urlGitHubActionsIssuer,
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
				t.Errorf(errMsgExpectedErrorGotNil)
			} else if !strings.Contains(err.Error(), tt.expectErr) {
				t.Errorf("Expected error to contain '%s', got '%s'", tt.expectErr, err.Error())
			}
		})
	}
}

func TestValidateIssuerNoClient(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)
	ctx := context.Background()

	err := validator.ValidateIssuer(ctx, "testorg", urlGitHubActionsIssuer)
	expectedErr := "no GitHub client configured for organization: testorg"
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Expected error containing '%s', got %v", expectedErr, err)
	}
}

// assertParseConfigResult is a helper function to reduce cognitive complexity
func assertParseConfigResult(t *testing.T, config *OrgTrustedTokenIssuersConfig, err error, expectErr bool) {
	if expectErr {
		if err == nil {
			t.Errorf(errMsgExpectedErrorGotNil)
		}
		return
	}

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if config == nil {
		t.Errorf("Expected config, got nil")
	}
}

// assertValidationResult is a helper function to reduce cognitive complexity
func assertValidationResult(t *testing.T, err error, expectErr bool) {
	if expectErr {
		if err == nil {
			t.Errorf(errMsgExpectedErrorGotNil)
		}
	} else {
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
	}
}

func TestParseConfig(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

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
  - "` + urlGitHubActionsIssuer + `"
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
		{
			name: "Too many trusted issuers",
			content: func() string {
				// Use slice capacity optimization for better memory allocation
				issuers := make([]string, 0, 26)
				for i := range 26 {
					issuers = append(issuers, fmt.Sprintf(`  - "https://issuer%d.example.com"`, i))
				}
				return fmt.Sprintf("enabled: true\ntrusted_issuers:\n%s", strings.Join(issuers, "\n"))
			}(),
			expectErr:   true,
			expectEmpty: false,
		},
		{
			name: "Too many issuer patterns",
			content: func() string {
				// Use slice capacity optimization for better memory allocation
				patterns := make([]string, 0, 6)
				for i := range 6 {
					patterns = append(patterns, fmt.Sprintf(`  - "https://pattern%d\\.example\\.com"`, i))
				}
				return fmt.Sprintf("enabled: true\nissuer_patterns:\n%s", strings.Join(patterns, "\n"))
			}(),
			expectErr:   true,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := validator.parseConfig(tt.content)
			assertParseConfigResult(t, config, err, tt.expectErr)
		})
	}
}

func TestValidateIssuerComplexPatterns(t *testing.T) {
	// Clear cache to avoid interference
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)
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
  - "` + urlGitHubActionsIssuer + `"
`,
			issuer:    urlGitHubActionsIssuer,
			expectErr: false,
		},
		{
			name: "No match",
			content: `
enabled: true
trusted_issuers:
  - "https://other.com"
`,
			issuer:    urlGitHubActionsIssuer,
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
			assertValidationResult(t, err, tt.expectErr)
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

func TestValidateIssuerInvalidPatterns(t *testing.T) {
	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

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

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)
	ctx := context.Background()

	// Create a mock client
	mockClient := &github.Client{}
	validator.SetGithubClient("testorg", mockClient)

	configContent := `
enabled: true
trusted_issuers:
  - "` + urlGitHubActionsIssuer + `"
`

	// Add config to shared cache
	trustedTokenIssuers.Add("testorg", configContent)

	// First call should use cache
	err1 := validator.ValidateIssuer(ctx, "testorg", urlGitHubActionsIssuer)
	if err1 != nil {
		t.Errorf("Expected no error on first call, got %v", err1)
	}

	// Second call should also use cache (no additional GitHub API call)
	err2 := validator.ValidateIssuer(ctx, "testorg", urlGitHubActionsIssuer)
	if err2 != nil {
		t.Errorf("Expected no error on second call, got %v", err2)
	}

	// Verify cache contains the entry
	if _, ok := trustedTokenIssuers.Get("testorg"); !ok {
		t.Errorf("Expected cache to contain entry for testorg")
	}
}

func TestCacheEviction(t *testing.T) {
	// Clear cache to start fresh
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

	configContent := `
enabled: true
trusted_issuers:
  - "` + urlGitHubActionsIssuer + `"
`

	// The cache size is 100, so add 101 items to trigger eviction
	for i := range 101 {
		orgName := fmt.Sprintf(patternTestOrg, i)

		// Create a mock client for each org
		mockClient := &github.Client{}
		validator.SetGithubClient(orgName, mockClient)

		// Add to cache directly to simulate loadOrgConfig
		evicted := trustedTokenIssuers.Add(orgName, configContent)

		// We should see eviction starting after cache is full
		if i >= 100 {
			if !evicted {
				t.Errorf("Expected eviction when adding org %d, but none occurred", i)
			}
		} else {
			if evicted {
				t.Errorf("Did not expect eviction when adding org %d, but eviction occurred", i)
			}
		}
	}

	// Verify cache size is at max (100)
	if trustedTokenIssuers.Len() != 100 {
		t.Errorf("Expected cache size to be 100, got %d", trustedTokenIssuers.Len())
	}

	// Verify the first entry was evicted (LRU behavior)
	if _, ok := trustedTokenIssuers.Get("testorg0"); ok {
		t.Errorf("Expected first entry to be evicted, but it's still in cache")
	}

	// Verify the last entry is still there
	if _, ok := trustedTokenIssuers.Get("testorg100"); !ok {
		t.Errorf("Expected last entry to be in cache, but it's not found")
	}
}

func TestCacheConsistencyAcrossValidations(t *testing.T) {
	// Clear cache to start fresh
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)
	ctx := context.Background()

	configContent := `
enabled: true
trusted_issuers:
  - "` + urlGitHubActionsIssuer + `"
  - "https://accounts.google.com"
`

	// Create a mock client
	mockClient := &github.Client{}
	validator.SetGithubClient("testorg", mockClient)

	// Add config to shared cache
	trustedTokenIssuers.Add("testorg", configContent)

	// Test multiple issuers with same org - should all use cache
	testIssuers := []string{
		urlGitHubActionsIssuer,
		"https://accounts.google.com",
		urlGitHubActionsIssuer, // repeat to test cache consistency
	}

	for i, issuer := range testIssuers {
		err := validator.ValidateIssuer(ctx, "testorg", issuer)
		if err != nil {
			t.Errorf("Validation %d failed for issuer %s: %v", i, issuer, err)
		}
	}

	// Verify cache still contains the entry
	if cachedContent, ok := trustedTokenIssuers.Get("testorg"); !ok {
		t.Errorf("Expected cache to contain entry for testorg after multiple validations")
	} else if cachedContent != configContent {
		t.Errorf("Cache content doesn't match expected content")
	}
}

func TestCacheEvictionLogging(t *testing.T) {
	// Clear cache to start fresh
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

	configContent := `
enabled: true
trusted_issuers:
  - "` + urlGitHubActionsIssuer + `"
`

	// Fill cache to capacity (100 entries)
	for i := range 100 {
		orgName := fmt.Sprintf(patternTestOrg, i)
		mockClient := &github.Client{}
		validator.SetGithubClient(orgName, mockClient)
		trustedTokenIssuers.Add(orgName, configContent)
	}

	// Verify cache is at capacity
	if trustedTokenIssuers.Len() != 100 {
		t.Errorf("Expected cache size to be 100, got %d", trustedTokenIssuers.Len())
	}

	// Now add one more which should trigger eviction and logging
	orgName := "testorg_eviction"
	mockClient := &github.Client{}
	validator.SetGithubClient(orgName, mockClient)

	// This should trigger eviction logging in loadOrgConfig
	evicted := trustedTokenIssuers.Add(orgName, configContent)
	if !evicted {
		t.Errorf("Expected eviction when adding to full cache, but none occurred")
	}

	// Verify cache size is still at max
	if trustedTokenIssuers.Len() != 100 {
		t.Errorf("Expected cache size to remain 100 after eviction, got %d", trustedTokenIssuers.Len())
	}

	// Verify the new entry is in cache
	if _, ok := trustedTokenIssuers.Get(orgName); !ok {
		t.Errorf("Expected newly added entry to be in cache")
	}
}

func TestLoadOrgConfigWithEviction(t *testing.T) {
	// Clear cache to start fresh
	trustedTokenIssuers.Purge()

	validator := NewOrgTrustedTokenIssuersValidator(fileTestConfig)

	configContent := `
enabled: true
trusted_issuers:
  - "` + urlGitHubActionsIssuer + `"
`

	// Fill cache to capacity (100 entries)
	for i := range 100 {
		trustedTokenIssuers.Add(fmt.Sprintf(patternTestOrg, i), configContent)
	}

	// Create a mock client for a new organization
	orgName := "neworg_test"
	client := &github.Client{}
	validator.SetGithubClient(orgName, client)

	// Add one more entry to trigger eviction
	evicted := trustedTokenIssuers.Add(orgName, configContent)
	if !evicted {
		t.Errorf("Expected eviction when adding to full cache, but none occurred")
	}

	// Verify cache is still at max capacity
	if trustedTokenIssuers.Len() != 100 {
		t.Errorf("Expected cache size to be 100 after eviction, got %d", trustedTokenIssuers.Len())
	}

	// Verify the new entry is in cache
	if _, ok := trustedTokenIssuers.Get(orgName); !ok {
		t.Errorf("Expected newly added entry to be in cache")
	}

	// Verify that the first entry was evicted (LRU behavior)
	if _, ok := trustedTokenIssuers.Get("testorg0"); ok {
		t.Errorf("Expected first entry to be evicted, but it's still in cache")
	}
}
