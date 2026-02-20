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

	kms "cloud.google.com/go/kms/apiv1"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghtransport"
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

	var client *kms.KeyManagementClient

	if baseCfg.KMSKey != "" {
		client, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			log.Panicf("could not create kms client: %v", err)
		}
	}

	transports := make(map[int64]*ghinstallation.AppsTransport, len(baseCfg.AppIDs))
	for _, appID := range baseCfg.AppIDs {
		atr, err := ghtransport.New(ctx, appID, baseCfg, client)
		if err != nil {
			log.Panicf("error creating GitHub App transport for app %d: %v", appID, err)
		}
		transports[appID] = atr
	}

	// Fetch webhook secrets from secret manager
	// or allow webhook secret to be defined by env var.
	// Not everyone is using Google KMS, so we need to support other methods
	webhookSecrets := [][]byte{}
	if baseCfg.KMSKey != "" {
		secretmanager, err := secretmanager.NewClient(ctx)
		if err != nil {
			log.Panicf("could not create secret manager client: %v", err)
		}
		for _, name := range strings.Split(webhookConfig.WebhookSecret, ",") {
			resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
				Name: name,
			})
			if err != nil {
				log.Panicf("error fetching webhook secret %s: %v", name, err)
			}
			webhookSecrets = append(webhookSecrets, resp.GetPayload().GetData())
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
		Transports:    transports,
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
