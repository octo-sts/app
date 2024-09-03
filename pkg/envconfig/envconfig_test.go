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
				"GITHUB_APP_ID":                 "1234",
				"KMS_KEY":                       "",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only KMS_KEY set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_ID":                 "1234",
				"KMS_KEY":                       "some-kms-key",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only APP_SECRET_CERTIFICATE_FILE set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_ID":                 "1234",
				"KMS_KEY":                       "",
				"APP_SECRET_CERTIFICATE_FILE":   "some-file-path",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: false,
		},
		{
			name: "Only APP_SECRET_CERTIFICATE_ENVVAR set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_ID":                 "1234",
				"KMS_KEY":                       "",
				"APP_SECRET_CERTIFICATE_FILE":   "",
				"APP_SECRET_CERTIFICATE_ENVVAR": "some-env-var",
			},
			wantErr: false,
		},
		{
			name: "Multiple variables set",
			envVars: map[string]string{
				"PORT":                          "8080",
				"GITHUB_APP_ID":                 "1234",
				"KMS_KEY":                       "some-kms-key",
				"APP_SECRET_CERTIFICATE_FILE":   "some-file-path",
				"APP_SECRET_CERTIFICATE_ENVVAR": "",
			},
			wantErr: true,
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
			wantErr: true,
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
