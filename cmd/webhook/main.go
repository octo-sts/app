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
	"github.com/chainguard-dev/octo-sts/pkg/gcpkms"
	"github.com/chainguard-dev/octo-sts/pkg/webhook"
	"github.com/kelseyhightower/envconfig"
)

type envConfig struct {
	Port          int    `envconfig:"PORT" required:"true" default:"8080"`
	KMSKey        string `envconfig:"KMS_KEY" required:"true"`
	AppID         int64  `envconfig:"GITHUB_APP_ID" required:"true"`
	WebhookSecret string `envconfig:"GITHUB_WEBHOOK_SECRET" required:"true"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx = clog.WithLogger(ctx, clog.New(slog.Default().Handler()))

	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Panicf("failed to process env var: %s", err)
	}

	kms, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Panicf("could not create kms client: %v", err)
	}
	signer, err := gcpkms.New(ctx, kms, env.KMSKey)
	if err != nil {
		log.Panicf("error creating signer: %v", err)
	}
	atr, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, env.AppID, ghinstallation.WithSigner(signer))
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}

	webhookSecrets := [][]byte{}
	secretmanager, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Panicf("could not create secret manager client: %v", err)
	}
	for _, name := range strings.Split(env.WebhookSecret, ",") {
		resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
			Name: name,
		})
		if err != nil {
			log.Panicf("error fetching webhook secret %s: %v", name, err)
		}
		webhookSecrets = append(webhookSecrets, resp.GetPayload().GetData())
	}

	validator := &webhook.Validator{
		Transport:     atr,
		WebhookSecret: webhookSecrets,
	}

	mux := http.NewServeMux()
	mux.Handle("/", validator)
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", env.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
	}
	log.Panic(srv.ListenAndServe())
}
