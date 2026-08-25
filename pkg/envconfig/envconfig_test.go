// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package envconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBaseConfig(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "No environment variables set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only KMS_KEYS set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "some-kms-key-1,some-kms-key-2",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only APP_SECRET_CERTIFICATE_FILE set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "",
				"APP_SECRET_CERTIFICATE_FILE":   "some-file-path",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only APP_SECRET_CERTIFICATE_ENVVAR set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "some-env-var",
			},
			wantErr: false,
		},
		{
			name: "Multiple variables set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "some-kms-key-1,some-kms-key-2",
				"APP_SECRET_CERTIFICATE_FILE":   "some-file-path",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: true,
		},
		{
			name: "KMS_KEYS length mismatch",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "some-kms-key-1",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: true,
		},
		{
			name: "KMS_KEYS with empty entry",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_IDS":                "12345678,87654321",
				"KMS_KEYS":                      "some-kms-key-1,",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			// Azure key identifiers are self-describing and travel in
			// KMS_KEYS, so they are validated by the generic KMS rules.
			name: "AKV keys supplied via KMS_KEYS",
			envVars: map[string]string{
				"PORT":           "8080",
				"GITHUB_APP_IDS": "12345678,87654321",
				"KMS_PROVIDER":   "akv",
				"KMS_KEYS":       "https://vault-a.vault.azure.net/keys/key-1,https://vault-b.vault.azure.net/keys/key-2/v2",
			},
			wantErr: false,
		},
		{
			name: "AKV keys length mismatch with app count",
			envVars: map[string]string{
				"PORT":           "8080",
				"GITHUB_APP_IDS": "12345678,87654321",
				"KMS_PROVIDER":   "akv",
				"KMS_KEYS":       "https://vault-a.vault.azure.net/keys/key-1",
			},
			wantErr: true,
		},
		{
			name: "Quota floors valid",
			envVars: map[string]string{
				"PORT":                     "8080",
				"GITHUB_APP_IDS":           "12345678",
				"OCTOSTS_QUOTA_FLOOR_HARD": "1500",
				"OCTOSTS_QUOTA_FLOOR_SOFT": "15000",
				"OCTOSTS_QUOTA_STALE":      "5m",
			},
			wantErr: false,
		},
		{
			name: "Quota soft floor must be >= hard floor",
			envVars: map[string]string{
				"PORT":                     "8080",
				"GITHUB_APP_IDS":           "12345678",
				"OCTOSTS_QUOTA_FLOOR_HARD": "5000",
				"OCTOSTS_QUOTA_FLOOR_SOFT": "1500",
			},
			wantErr: true,
		},
		{
			name: "Quota floors equal is allowed",
			envVars: map[string]string{
				"PORT":                     "8080",
				"GITHUB_APP_IDS":           "12345678",
				"OCTOSTS_QUOTA_FLOOR_HARD": "1500",
				"OCTOSTS_QUOTA_FLOOR_SOFT": "1500",
			},
			wantErr: false,
		},
		{
			name: "Negative floor rejected",
			envVars: map[string]string{
				"PORT":                     "8080",
				"GITHUB_APP_IDS":           "12345678",
				"OCTOSTS_QUOTA_FLOOR_HARD": "-1",
			},
			wantErr: true,
		},
		{
			name: "Zero stale duration rejected",
			envVars: map[string]string{
				"PORT":                "8080",
				"GITHUB_APP_IDS":      "12345678",
				"OCTOSTS_QUOTA_STALE": "0s",
			},
			wantErr: true,
		},
		{
			name: "Negative stale duration rejected",
			envVars: map[string]string{
				"PORT":                "8080",
				"GITHUB_APP_IDS":      "12345678",
				"OCTOSTS_QUOTA_STALE": "-5m",
			},
			wantErr: true,
		},
		{
			name: "Sticky store firestore valid",
			envVars: map[string]string{
				"PORT":                               "8080",
				"GITHUB_APP_IDS":                     "12345678",
				"OCTOSTS_STICKY_STORE":               "firestore",
				"OCTOSTS_STICKY_STORE_FIRESTORE_TTL": "1h",
			},
			wantErr: false,
		},
		{
			name: "Sticky store disabled by default",
			envVars: map[string]string{
				"PORT":           "8080",
				"GITHUB_APP_IDS": "12345678",
			},
			wantErr: false,
		},
		{
			name: "Sticky store invalid backend rejected",
			envVars: map[string]string{
				"PORT":                 "8080",
				"GITHUB_APP_IDS":       "12345678",
				"OCTOSTS_STICKY_STORE": "redis",
			},
			wantErr: true,
		},
		{
			name: "Sticky store negative TTL rejected",
			envVars: map[string]string{
				"PORT":                               "8080",
				"GITHUB_APP_IDS":                     "12345678",
				"OCTOSTS_STICKY_STORE":               "firestore",
				"OCTOSTS_STICKY_STORE_FIRESTORE_TTL": "-1h",
			},
			wantErr: true,
		},
		{
			name: "GITHUB_BASE_URL valid HTTPS",
			envVars: map[string]string{
				"PORT":            "8080",
				"GITHUB_APP_IDS":  "12345678",
				"GITHUB_BASE_URL": "https://github.example.com/api/v3",
			},
			wantErr: false,
		},
		{
			name: "GITHUB_BASE_URL rejects HTTP",
			envVars: map[string]string{
				"PORT":            "8080",
				"GITHUB_APP_IDS":  "12345678",
				"GITHUB_BASE_URL": "http://github.example.com/api/v3",
			},
			wantErr: true,
		},
		{
			name: "GITHUB_BASE_URL rejects invalid URL",
			envVars: map[string]string{
				"PORT":            "8080",
				"GITHUB_APP_IDS":  "12345678",
				"GITHUB_BASE_URL": "://not-a-url",
			},
			wantErr: true,
		},
		{
			name: "GITHUB_BASE_URL empty is allowed",
			envVars: map[string]string{
				"PORT":            "8080",
				"GITHUB_APP_IDS":  "12345678",
				"GITHUB_BASE_URL": "",
			},
			wantErr: false,
		},
		{
			// BaseConfig only records the path; the file is read later by
			// pkg/appconfig, so it doesn't need to exist here.
			name: "APP_CONFIG_FILE set bypasses GITHUB_APP_IDS requirement",
			envVars: map[string]string{
				"PORT":            "8080",
				"APP_CONFIG_FILE": "/etc/octo-sts/config.yaml",
			},
			wantErr: false,
		},
		{
			name: "GITHUB_APP_IDS required when APP_CONFIG_FILE unset",
			envVars: map[string]string{
				"PORT": "8080",
			},
			wantErr: true,
		},
		{
			// Legacy credential validation is skipped by design when the
			// YAML config is in use: credentials come from the config file,
			// so conflicting legacy env vars are ignored rather than fatal.
			name: "APP_CONFIG_FILE skips legacy credential validation",
			envVars: map[string]string{
				"PORT":                        "8080",
				"APP_CONFIG_FILE":             "/etc/octo-sts/config.yaml",
				"GITHUB_APP_IDS":              "12345678,87654321",
				"KMS_KEYS":                    "only-one-key",
				"APP_SECRET_CERTIFICATE_FILE": "some-file-path",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			cfg, err := BaseConfig()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

func TestAppConfig(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "No environment variables set",
			envVars: map[string]string{
				"STS_DOMAIN":        "",
				"EVENT_INGRESS_URI": "",
			},
			wantErr: false,
		},
		{
			name: "All environment variables set",
			envVars: map[string]string{
				"STS_DOMAIN":        "octo-sts-test.local",
				"EVENT_INGRESS_URI": "http://localhost:8082",
			},
			wantErr: false,
		},
		{
			name: "Missing Event Ingress URI",
			envVars: map[string]string{
				"STS_DOMAIN": "octo-sts-test.local",
			},
			wantErr: false,
		},
		{
			name: "ORG_POLICY_REPO explicitly empty rejected",
			envVars: map[string]string{
				"STS_DOMAIN":      "octo-sts-test.local",
				"ORG_POLICY_REPO": "",
			},
			wantErr: true,
		},
		{
			name: "ORG_POLICY_REPO custom value accepted",
			envVars: map[string]string{
				"STS_DOMAIN":      "octo-sts-test.local",
				"ORG_POLICY_REPO": "my-policies",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			cfg, err := AppConfig()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

func TestWebhookConfig(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
	}{
		{
			name: "No environment variables set",
			envVars: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "",
			},
			wantErr: false,
		},
		{
			name: "All environment variables set",
			envVars: map[string]string{
				"GITHUB_WEBHOOK_SECRET": "octo-sts-test.local",
			},
			wantErr: false,
		},
		{
			name:    "Missing Event Ingress URI",
			envVars: map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, value := range tt.envVars {
				t.Setenv(key, value)
			}

			cfg, err := WebhookConfig()

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
			}
		})
	}
}

// TestValidateRateLimit covers the settings that would otherwise disable
// enforcement silently: an unknown store name, a non-positive window, and
// redis selected without the settings it needs to reach a server.
func TestValidateRateLimit(t *testing.T) {
	base := func(mutate func(*EnvConfig)) *EnvConfig {
		cfg := &EnvConfig{
			RateLimit:       100,
			RateLimitWindow: 5 * time.Minute,
		}
		mutate(cfg)
		return cfg
	}

	tests := []struct {
		name    string
		cfg     *EnvConfig
		wantErr string
	}{
		{
			name: "disabled by default",
			cfg:  base(func(*EnvConfig) {}),
		},
		{
			name: "memory needs no store settings",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "memory"
			}),
		},
		{
			name: "unknown store",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "redsi"
			}),
			wantErr: "is not supported",
		},
		{
			// A zero window expires every bucket immediately, which admits
			// every request while appearing to be configured.
			name: "non-positive window",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "memory"
				c.RateLimitWindow = 0
			}),
			wantErr: "must be positive",
		},
		{
			name: "non-positive limit",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "memory"
				c.RateLimit = 0
			}),
			wantErr: "must be positive",
		},
		{
			name: "redis without a URL",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "redis"
				c.RateLimitRedisAuth = "none"
			}),
			wantErr: "OCTOSTS_REDIS_URL is required",
		},
		{
			name: "redis with entra auth but no address",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "redis"
				c.RateLimitRedisAuth = "entra"
			}),
			wantErr: "OCTOSTS_REDIS_ADDR is required",
		},
		{
			name: "redis with an unknown auth mode",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "redis"
				c.RateLimitRedisAuth = "iam"
				c.RateLimitRedisURL = "rediss://example:6380"
			}),
			wantErr: "is not supported",
		},
		{
			name: "redis configured correctly",
			cfg: base(func(c *EnvConfig) {
				c.RateLimitStore = "redis"
				c.RateLimitRedisAuth = "none"
				c.RateLimitRedisURL = "rediss://example:6380"
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRateLimit(tt.cfg)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
