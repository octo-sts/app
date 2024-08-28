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

	atr, err := ghtransport.New(ctx, baseCfg, client)
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}

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

	mux := http.NewServeMux()
	mux.Handle("/", &webhook.Validator{
		Transport:     atr,
		WebhookSecret: webhookSecrets,
	})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", baseCfg.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
	}
	log.Panic(srv.ListenAndServe())
}
