// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package envconfig

import (
	"testing"

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
