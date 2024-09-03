// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package envconfig

import (
	"errors"

	"github.com/kelseyhightower/envconfig"
)

type EnvConfig struct {
	Port                       int    `envconfig:"PORT" required:"true"`
	KMSKey                     string `envconfig:"KMS_KEY" required:"false"`
	AppID                      int64  `envconfig:"GITHUB_APP_ID" required:"true"`
	AppSecretCertificateFile   string `envconfig:"APP_SECRET_CERTIFICATE_FILE" required:"false"`
	AppSecretCertificateEnvVar string `envconfig:"APP_SECRET_CERTIFICATE_ENV_VAR" required:"false"`
	Metrics                    bool   `envconfig:"METRICS" required:"false" default:"true"`
}

type EnvConfigApp struct {
	Domain          string `envconfig:"STS_DOMAIN" required:"true"`
	EventingIngress string `envconfig:"EVENT_INGRESS_URI" required:"true"`
}

type EnvConfigWebhook struct {
	WebhookSecret string `envconfig:"WEBHOOK_SECRET" required:"true"`
	// If set, only process events from these organizations (comma separated).
	OrganizationFilter string `envconfig:"GITHUB_ORGANIZATION_FILTER"`
}

func AppConfig() (*EnvConfigApp, error) {
	cfg := new(EnvConfigApp)

	var err error
	if err = envconfig.Process("", cfg); err != nil {
		return nil, err
	}

	return cfg, err
}

func WebhookConfig() (*EnvConfigWebhook, error) {
	cfg := new(EnvConfigWebhook)

	var err error
	if err = envconfig.Process("", cfg); err != nil {
		return nil, err
	}

	return cfg, err
}

func BaseConfig() (*EnvConfig, error) {
	cfg := new(EnvConfig)

	var err error
	if err = envconfig.Process("", cfg); err != nil {
		return nil, err
	}

	kmsSet := false
	for _, v := range []string{cfg.KMSKey, cfg.AppSecretCertificateFile, cfg.AppSecretCertificateEnvVar} {
		if v != "" {
			if kmsSet {
				return nil, errors.New("only one of KMS_KEY, APP_SECRET_CERTIFICATE_FILE, APP_SECRET_CERTIFICATE_ENV_VAR may be set")
			}
			kmsSet = true
		}
	}

	return cfg, err
}
