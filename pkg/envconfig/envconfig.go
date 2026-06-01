// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package envconfig

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type EnvConfig struct {
	Port                       int      `envconfig:"PORT" required:"true"`
	KMSKeys                    []string `envconfig:"KMS_KEYS" required:"false"`
	AppIDs                     []int64  `envconfig:"GITHUB_APP_IDS" required:"true"`
	AppSecretCertificateFile   string   `envconfig:"APP_SECRET_CERTIFICATE_FILE" required:"false"`
	AppSecretCertificateEnvVar string   `envconfig:"APP_SECRET_CERTIFICATE_ENV_VAR" required:"false"`
	Metrics                    bool     `envconfig:"METRICS" required:"false" default:"true"`
	// QuotaFloorHard / QuotaFloorSoft tune the three-tier capacity-aware
	// picker in pkg/ghinstall. Defaults target GitHub's default 15,000/hr
	// installation rate-limit cap: drop out of the preferred pool below
	// ~33% remaining (5,000), exclude entirely below ~10% remaining (1,500).
	// Operators with elevated installation tiers (50,000/hr) should raise
	// SOFT to roughly the lowest cap in their pool so high-cap installs are
	// preferred while they have at least one low-cap-worth of headroom.
	QuotaFloorHard  int           `envconfig:"OCTOSTS_QUOTA_FLOOR_HARD" required:"false" default:"1500"`
	QuotaFloorSoft  int           `envconfig:"OCTOSTS_QUOTA_FLOOR_SOFT" required:"false" default:"5000"`
	QuotaStaleAfter time.Duration `envconfig:"OCTOSTS_QUOTA_STALE" required:"false" default:"5m"`

	StickyStore                    string        `envconfig:"OCTOSTS_STICKY_STORE" required:"false"`
	StickyStoreFirestoreProject    string        `envconfig:"OCTOSTS_STICKY_STORE_FIRESTORE_PROJECT" required:"false"`
	StickyStoreFirestoreCollection string        `envconfig:"OCTOSTS_STICKY_STORE_FIRESTORE_COLLECTION" required:"false" default:"sticky-routes"`
	StickyStoreFirestoreTTL        time.Duration `envconfig:"OCTOSTS_STICKY_STORE_FIRESTORE_TTL" required:"false" default:"1h"`

	// GitHubBaseURL overrides the GitHub API base URL for GitHub Enterprise
	// Server deployments (e.g. "https://github.example.com/api/v3").
	// When empty, the default https://api.github.com is used.
	GitHubBaseURL string `envconfig:"GITHUB_BASE_URL" required:"false"`
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
	if cfg.QuotaStaleAfter <= 0 {
		return nil, fmt.Errorf("OCTOSTS_QUOTA_STALE (%s) must be positive", cfg.QuotaStaleAfter)
	}

	if cfg.StickyStore != "" && cfg.StickyStore != "firestore" && cfg.StickyStore != "memory" {
		return nil, fmt.Errorf("OCTOSTS_STICKY_STORE %q is not supported (valid: memory, firestore)", cfg.StickyStore)
	}
	if cfg.StickyStore == "firestore" && cfg.StickyStoreFirestoreTTL <= 0 {
		return nil, fmt.Errorf("OCTOSTS_STICKY_STORE_FIRESTORE_TTL (%s) must be positive", cfg.StickyStoreFirestoreTTL)
	}

	if cfg.GitHubBaseURL != "" {
		u, err := url.Parse(cfg.GitHubBaseURL)
		if err != nil {
			return nil, fmt.Errorf("GITHUB_BASE_URL is not a valid URL: %w", err)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("GITHUB_BASE_URL must use https scheme, got %q", u.Scheme)
		}
	}

	return cfg, err
}
