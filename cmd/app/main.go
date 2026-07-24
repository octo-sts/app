// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"chainguard.dev/go-grpc-kit/pkg/duplex"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	mce "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics/cloudevents"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/octosts"
	"github.com/octo-sts/app/pkg/stickystore"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx = clog.WithLogger(ctx, clog.New(slog.Default().Handler()))

	baseCfg, err := envConfig.BaseConfig()
	if err != nil {
		log.Panicf("failed to process env var: %s", err)
	}
	appConfig, err := envConfig.AppConfig()
	if err != nil {
		log.Panicf("failed to process env var: %s", err)
	}

	if baseCfg.Metrics {
		go metrics.ServeMetrics()

		// Setup tracing.
		defer metrics.SetupTracer(ctx)()
	}

	var client *kms.KeyManagementClient

	if len(baseCfg.KMSKeys) > 0 {
		client, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			log.Panicf("could not create kms client: %v", err)
		}
	}

	// Capacity-aware routing: a shared QuotaStore is populated by the
	// transport tap (X-RateLimit-Remaining headers on every GitHub response)
	// and read by NewRoundRobinWithQuota. Cold start (no quota data yet)
	// safely falls back to the atomic-counter strategy. Check-run ownership
	// for checks:write policies is handled by the sticky store.
	quotaStore := ghinstall.NewQuotaStore(baseCfg.QuotaStaleAfter)
	quotaCfg := &ghinstall.QuotaConfig{
		Store:     quotaStore,
		SoftFloor: baseCfg.QuotaFloorSoft,
		HardFloor: baseCfg.QuotaFloorHard,
	}

	managers := make([]ghinstall.Manager, 0, len(baseCfg.AppIDs))
	for i, appID := range baseCfg.AppIDs {
		var kmsKey string
		if len(baseCfg.KMSKeys) > 0 {
			kmsKey = baseCfg.KMSKeys[i]
			if kmsKey == "" {
				log.Printf("skipping app %d: no KMS key configured", appID)
				continue
			}
		}
		atr, err := ghtransport.New(ctx, appID, kmsKey, baseCfg, client, quotaStore)
		if err != nil {
			log.Panicf("error creating GitHub App transport for app %d: %v", appID, err)
		}
		m, err := ghinstall.New(atr)
		if err != nil {
			log.Panicf("error creating install manager for app %d: %v", appID, err)
		}
		managers = append(managers, m)
	}
	if len(managers) == 0 {
		log.Panic("no apps with valid KMS keys configured")
	}

	var rrm ghinstall.Manager
	var sticky stickystore.Store
	if len(managers) == 1 {
		rrm = ghinstall.NewRoundRobin(managers)
	} else {
		rrm = ghinstall.NewRoundRobinWithQuota(managers, quotaCfg)
	}
	if len(managers) > 1 && baseCfg.StickyStore != "" {
		var closer io.Closer
		sticky, closer, err = stickystore.New(ctx, baseCfg)
		if err != nil {
			log.Panicf("failed to create sticky store: %v", err)
		}
		defer closer.Close()
	}

	d := duplex.New(
		baseCfg.Port,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	var ceclient cloudevents.Client
	if baseCfg.Metrics {
		ceclient, err = mce.NewClientHTTP("octo-sts", mce.WithTarget(ctx, appConfig.EventingIngress)...)
		if err != nil {
			log.Panicf("failed to create cloudevents client: %v", err)
		}
	}

	pboidc.RegisterSecurityTokenServiceServer(d.Server, octosts.NewSecurityTokenServiceServer(rrm, sticky, len(managers), ceclient, appConfig.Domain, baseCfg.Metrics, appConfig.OrgPolicyRepo))
	if err := d.RegisterHandler(ctx, pboidc.RegisterSecurityTokenServiceHandlerFromEndpoint); err != nil {
		log.Panicf("failed to register gateway endpoint: %v", err)
	}

	if err := d.MUX.HandlePath(http.MethodGet, "/", func(w http.ResponseWriter, r *http.Request, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		s := `{"msg": "please check documentation for usage: https://github.com/octo-sts/app"}`
		if _, err := w.Write([]byte(s)); err != nil {
			log.Printf("Failed to write bytes back to client: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}); err != nil {
		log.Panicf("failed to register root GET handler: %v", err)
	}

	// Register health check service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(d.Server, healthServer)

	if err := d.ListenAndServe(ctx); err != nil {
		log.Panicf("ListenAndServe() = %v", err)
	}

	// This will block until a signal arrives.
	<-ctx.Done()
}
