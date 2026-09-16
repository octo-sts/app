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
	"syscall"
	"time"

	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	mce "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics/cloudevents"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/kms"
	"github.com/octo-sts/app/pkg/secrets"
	"github.com/octo-sts/app/pkg/webhook"
)

// Shutdown is bounded so both phases fit inside the grace period a platform
// allows between SIGTERM and SIGKILL. Cloud Run's default is the tighter of
// the two at 10s (Kubernetes allows 30s), and overrunning it means a hard kill
// that drops whatever is still queued — so the budget targets the tighter one.
// The server drains first, letting in-flight webhooks finish and enqueue their
// events, then the emitter drains what it holds.
const (
	serverDrainTimeout  = 3 * time.Second
	emitterDrainTimeout = 6 * time.Second
)

func main() {
	// Cloud Run and Kubernetes both stop a container by sending SIGTERM, so it
	// has to be caught for any of the shutdown work below to happen at all:
	// Go's default disposition for SIGTERM terminates the process outright,
	// running no deferred functions and dropping any queued events on the
	// floor. SIGINT is caught too, for parity when run locally.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
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

	// Deliberately not gated on baseCfg.Metrics, unlike the STS exchange
	// stream: these events are the detection signal for trust policy changes, and
	// turning off metrics must not silently turn off a security control.
	var emitter *webhook.PolicyEmitter
	if webhookConfig.EventingIngress != "" {
		ceclient, err := mce.NewClientHTTP("octo-sts-webhook", mce.WithTarget(ctx, webhookConfig.EventingIngress)...)
		if err != nil {
			log.Panicf("failed to create cloudevents client: %v", err)
		}
		emitter = webhook.NewPolicyEmitter(ceclient)
	} else {
		clog.FromContext(ctx).Warn("EVENT_INGRESS_URI unset; trust policy events will not be emitted")
	}

	// Only use the primary app ID and KMS key for the webhook transport.
	var appID int64
	if len(baseCfg.AppIDs) > 0 {
		appID = baseCfg.AppIDs[0]
	} else {
		log.Panic("at least one GitHub App ID must be provided")
	}

	// If kmsKey remains empty, ghtransport.New() will fall back on
	// APP_SECRET_CERTIFICATE_FILE or APP_SECRET_CERTIFICATE_ENV_VAR.
	var kmsKey string
	var kmsClient kms.KMS
	if len(baseCfg.KMSKeys) > 0 {
		kmsKey = baseCfg.KMSKeys[0]
		kmsClient, err = kms.NewKMS(ctx, baseCfg.KMSProvider, kmsKey)
		if err != nil {
			log.Panicf("could not create kms client: %v", err)
		}
		defer kmsClient.Close() //nolint:errcheck // released at process shutdown
	}

	atr, err := ghtransport.New(ctx, appID, kmsKey, baseCfg, kmsClient, nil)
	if err != nil {
		log.Panicf("error creating GitHub App transport for app %d: %v", appID, err)
	}

	// Fetch webhook secrets from secret manager
	// or allow webhook secret to be defined by env var.
	// Not everyone is using a supported cloud provider, so we need to support other methods
	webhookSecrets := [][]byte{}
	if len(baseCfg.KMSKeys) > 0 {
		// It's probably not ideal to assume the secret provider is the same as the KMS
		// provider, but because of the support for environment variables before adding a
		// second cloud provider supported, that complicates adding a new environment variable
		// for config.
		secretsProvider, err := secrets.NewSecretProvider(ctx, baseCfg.KMSProvider)
		if err != nil {
			log.Panicf("could not create secret provider: %v", err)
		}
		defer secretsProvider.Close() //nolint:errcheck // released at process shutdown
		for name := range strings.SplitSeq(webhookConfig.WebhookSecret, ",") {
			name = strings.TrimSpace(name)
			val, err := secretsProvider.GetSecret(ctx, name)
			if err != nil {
				log.Panicf("error fetching webhook secret %s: %v", name, err)
			}
			webhookSecrets = append(webhookSecrets, val)
		}
	} else {
		webhookSecrets = [][]byte{[]byte(webhookConfig.WebhookSecret)}
	}

	var orgs []string
	for s := range strings.SplitSeq(webhookConfig.OrganizationFilter, ",") {
		if o := strings.TrimSpace(s); o != "" {
			orgs = append(orgs, o)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", &webhook.Validator{
		Transport:     atr,
		WebhookSecret: webhookSecrets,
		Organizations: orgs,
		OrgPolicyRepo: webhookConfig.OrgPolicyRepo,
		Emitter:       emitter,
	})
	mux.HandleFunc("/healthcheck", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", baseCfg.Port),
		ReadHeaderTimeout: 10 * time.Second,
		Handler:           mux,
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe() }()

	select {
	case err := <-serveErr:
		// The listener failed on its own; nothing to drain gracefully from.
		log.Panic(err)
	case <-ctx.Done():
		clog.FromContext(ctx).Info("shutdown signal received, draining")
	}

	// From here the signal context is already cancelled, so every deadline
	// below has to be built on a context that outlives it.
	base := context.WithoutCancel(ctx)

	// Stop taking new deliveries and let in-flight webhooks finish, so their
	// events reach the queue before it closes. If a handler outlives this
	// deadline it keeps running, and its Enqueue lands after the queue has
	// closed — which the emitter drops and counts rather than panicking on.
	sctx, scancel := context.WithTimeout(base, serverDrainTimeout)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		clog.FromContext(ctx).Errorf("http server did not shut down cleanly: %v", err)
	}

	if emitter != nil {
		ectx, ecancel := context.WithTimeout(base, emitterDrainTimeout)
		defer ecancel()
		if err := emitter.Shutdown(ectx); err != nil {
			clog.FromContext(ctx).Errorf("policy emitter did not drain: %v", err)
		}
	}
}
