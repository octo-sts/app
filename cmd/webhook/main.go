// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/kms"
	"github.com/octo-sts/app/pkg/secrets"
	"github.com/octo-sts/app/pkg/webhook"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx = clog.WithLogger(ctx, clog.New(slog.Default().Handler()))

	baseCfg, err := envConfig.BaseConfig()
	if err != nil {
		log.Panicf("failed to process env var: %s", err)
	}
	webhookConfig, err := envConfig.WebhookConfig()
	if err != nil {
		log.Panicf("failed to process env var: %s", err)
	}

	if baseCfg.Metrics {
		go metrics.ServeMetrics()

		// Setup tracing.
		defer metrics.SetupTracer(ctx)()
	}

	var kmsClient kms.KMS

	if baseCfg.KMSKey != "" {
		kmsClient, err = kms.NewKMS(ctx, baseCfg.KMSProvider, baseCfg.KMSKey)
		if err != nil {
			log.Panicf("could not create kms client: %v", err)
		}
	}

	atr, err := ghtransport.New(ctx, baseCfg, kmsClient)
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}

	// Fetch webhook secrets from secret manager
	// or allow webhook secret to be defined by env var.
	// Not everyone is using a supported cloud provider, so we need to support other methods
	webhookSecrets := [][]byte{}
	if baseCfg.KMSKey != "" {
		// It's probably not ideal to assume the secret provider is the same as the KMS
		//provider, but because of the support for environment variables before adding a
		//second cloud provider supported, that complicates adding a new environment variable
		//for config.
		secretsProvider, err := secrets.NewSecretProvider(ctx, baseCfg.KMSProvider)
		if err != nil {
			log.Panicf("could not create secret provider: %v", err)
		}
		for _, name := range strings.Split(webhookConfig.WebhookSecret, ",") {
			val, err := secretsProvider.GetSecret(name)
			if err != nil {
				log.Panicf("error fetching webhook secret %s: %v", name, err)
			}
			webhookSecrets = append(webhookSecrets, val)
		}
	} else {
		webhookSecrets = [][]byte{[]byte(webhookConfig.WebhookSecret)}
	}

	var orgs []string
	for _, s := range strings.Split(webhookConfig.OrganizationFilter, ",") {
		if o := strings.TrimSpace(s); o != "" {
			orgs = append(orgs, o)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", &webhook.Validator{
		Transport:     atr,
		WebhookSecret: webhookSecrets,
		Organizations: orgs,
	})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", baseCfg.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
	}
	log.Panic(srv.ListenAndServe())
}
