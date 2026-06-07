// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
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

	"github.com/octo-sts/app/pkg/appconfig"
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
	appCfg, err := envConfig.AppConfig()
	if err != nil {
		log.Panicf("failed to process env var: %s", err)
	}

	if baseCfg.Metrics {
		go metrics.ServeMetrics()
		defer metrics.SetupTracer(ctx)()
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

	var router *ghinstall.OrgRouter
	var totalApps int
	if baseCfg.AppConfigFile != "" {
		router, totalApps, err = buildRouterFromYAML(ctx, baseCfg.AppConfigFile, quotaStore, quotaCfg)
		if err != nil {
			log.Panicf("failed to build router from YAML config: %v", err)
		}
	} else {
		router, totalApps, err = buildRouterFromEnv(ctx, baseCfg, quotaStore, quotaCfg)
		if err != nil {
			log.Panicf("failed to build router from env vars: %v", err)
		}
	}

	// Sticky store is shared across all org pools. Installation IDs are
	// globally unique within GitHub, so a single store has no key collisions
	// across orgs. Only enable when there are multiple apps in flight; with
	// one app there is nothing to balance.
	var sticky stickystore.Store
	if totalApps > 1 && baseCfg.StickyStore != "" {
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
		ceclient, err = mce.NewClientHTTP("octo-sts", mce.WithTarget(ctx, appCfg.EventingIngress)...)
		if err != nil {
			log.Panicf("failed to create cloudevents client: %v", err)
		}
	}

	pboidc.RegisterSecurityTokenServiceServer(d.Server, octosts.NewSecurityTokenServiceServer(router, sticky, ceclient, appCfg.Domain, baseCfg.Metrics))
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

// buildPool builds an OrgPool from a slice of managers, choosing
// quota-aware round-robin when multiple apps are present and plain
// round-robin otherwise (no quota data to consult with a single app).
func buildPool(managers []ghinstall.Manager, quotaCfg *ghinstall.QuotaConfig) *ghinstall.OrgPool {
	var m ghinstall.Manager
	if len(managers) == 1 {
		m = ghinstall.NewRoundRobin(managers)
	} else {
		m = ghinstall.NewRoundRobinWithQuota(managers, quotaCfg)
	}
	return &ghinstall.OrgPool{M: m, AppCount: len(managers)}
}

// buildRouterFromYAML loads the YAML config file and builds an OrgRouter
// with per-org app pools. The quotaStore is shared across every pool so
// the capacity-aware picker sees the full per-installation rate-limit
// state regardless of which org's pool issued the request.
func buildRouterFromYAML(ctx context.Context, configFile string, quotaStore *ghinstall.QuotaStore, quotaCfg *ghinstall.QuotaConfig) (*ghinstall.OrgRouter, int, error) {

	options := []appconfig.OptionsApplier{
		appconfig.WithConfigFilePath(configFile),
	}

	cfg, err := appconfig.Load(options...)
	if err != nil {
		return nil, 0, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, 0, err
	}

	// Create KMS client only if any app uses kms_key.
	var kmsClient *kms.KeyManagementClient
	for _, org := range cfg.Orgs {
		for _, app := range org.Apps {
			if app.KMSKey != "" {
				kmsClient, err = kms.NewKeyManagementClient(ctx)
				if err != nil {
					return nil, 0, err
				}
				break
			}
		}
		if kmsClient != nil {
			break
		}
	}

	pools := make(map[string]*ghinstall.OrgPool, len(cfg.Orgs))
	totalApps := 0
	for _, org := range cfg.Orgs {
		managers := make([]ghinstall.Manager, 0, len(org.Apps))
		for _, app := range org.Apps {
			atr, err := ghtransport.NewFromAppConfig(ctx, app, kmsClient, quotaStore)
			if err != nil {
				return nil, 0, err
			}
			m, err := ghinstall.New(atr)
			if err != nil {
				return nil, 0, err
			}
			managers = append(managers, m)
		}
		pools[org.Name] = buildPool(managers, quotaCfg)
		totalApps += len(managers)
	}

	return ghinstall.NewOrgRouter(pools), totalApps, nil
}

// buildRouterFromEnv creates an OrgRouter from legacy environment variables.
// All apps are placed in a wildcard pool that serves any org.
func buildRouterFromEnv(ctx context.Context, baseCfg *envConfig.EnvConfig, quotaStore *ghinstall.QuotaStore, quotaCfg *ghinstall.QuotaConfig) (*ghinstall.OrgRouter, int, error) {
	var kmsClient *kms.KeyManagementClient
	var err error

	if len(baseCfg.KMSKeys) > 0 {
		kmsClient, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, 0, err
		}
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
		atr, err := ghtransport.New(ctx, appID, kmsKey, baseCfg, kmsClient, quotaStore)
		if err != nil {
			return nil, 0, err
		}
		m, err := ghinstall.New(atr)
		if err != nil {
			return nil, 0, err
		}
		managers = append(managers, m)
	}
	if len(managers) == 0 {
		return nil, 0, fmt.Errorf("no apps with valid KMS keys configured")
	}

	return ghinstall.NewOrgRouter(map[string]*ghinstall.OrgPool{
		ghinstall.WildcardOrg: buildPool(managers, quotaCfg),
	}), len(managers), nil
}
