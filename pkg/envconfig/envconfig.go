// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package envconfig

import (
	"errors"
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type EnvConfig struct {
	Port                       int           `envconfig:"PORT" required:"true"`
	KMSKeys                    []string      `envconfig:"KMS_KEYS" required:"false"`
	AppIDs                     []int64       `envconfig:"GITHUB_APP_IDS" required:"true"`
	AppSecretCertificateFile   string        `envconfig:"APP_SECRET_CERTIFICATE_FILE" required:"false"`
	AppSecretCertificateEnvVar string        `envconfig:"APP_SECRET_CERTIFICATE_ENV_VAR" required:"false"`
	Metrics                    bool          `envconfig:"METRICS" required:"false" default:"true"`
	QuotaFloorHard             int           `envconfig:"OCTOSTS_QUOTA_FLOOR_HARD" required:"false" default:"1500"`
	QuotaFloorSoft             int           `envconfig:"OCTOSTS_QUOTA_FLOOR_SOFT" required:"false" default:"15000"`
	QuotaStaleAfter            time.Duration `envconfig:"OCTOSTS_QUOTA_STALE" required:"false" default:"5m"`
}

type EnvConfigApp struct {
	Domain          string `envconfig:"STS_DOMAIN" required:"true"`
	EventingIngress string `envconfig:"EVENT_INGRESS_URI" required:"false"`
}

type EnvConfigWebhook struct {
	WebhookSecret string `envconfig:"GITHUB_WEBHOOK_SECRET" required:"true"`
	// If set, only process events from these organizations (comma separated).
	OrganizationFilter string `envconfig:"GITHUB_WEBHOOK_ORGANIZATION_FILTER"`
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

	sources := 0
	if len(cfg.KMSKeys) > 0 {
		sources++
	}
	if cfg.AppSecretCertificateFile != "" {
		sources++
	}
	if cfg.AppSecretCertificateEnvVar != "" {
		sources++
	}
	if sources > 1 {
		return nil, errors.New("only one of KMS_KEYS, APP_SECRET_CERTIFICATE_FILE, APP_SECRET_CERTIFICATE_ENV_VAR may be set")
	}

	if len(cfg.KMSKeys) > 0 && len(cfg.KMSKeys) != len(cfg.AppIDs) {
		return nil, fmt.Errorf("KMS_KEYS length (%d) must match GITHUB_APP_IDS length (%d)", len(cfg.KMSKeys), len(cfg.AppIDs))
	}

	if cfg.QuotaFloorHard < 0 || cfg.QuotaFloorSoft < 0 {
		return nil, errors.New("OCTOSTS_QUOTA_FLOOR_HARD and OCTOSTS_QUOTA_FLOOR_SOFT must be non-negative")
	}
	if cfg.QuotaFloorSoft < cfg.QuotaFloorHard {
		return nil, fmt.Errorf("OCTOSTS_QUOTA_FLOOR_SOFT (%d) must be >= OCTOSTS_QUOTA_FLOOR_HARD (%d)", cfg.QuotaFloorSoft, cfg.QuotaFloorHard)
	}

	return cfg, err
}
