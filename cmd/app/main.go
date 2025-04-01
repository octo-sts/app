// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"os"
	"os/signal"

	"chainguard.dev/go-grpc-kit/pkg/duplex"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	mce "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics/cloudevents"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghtransport"
	"github.com/octo-sts/app/pkg/octosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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

	d := duplex.New(
		baseCfg.Port,
		// grpc.StatsHandler(otelgrpc.NewServerHandler()),
		// grpc.ChainStreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		// grpc.ChainUnaryInterceptor(grpc_prometheus.UnaryServerInterceptor, interceptors.ServerErrorInterceptor),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
		})),
	)

	ceclient, err := mce.NewClientHTTP("octo-sts", mce.WithTarget(ctx, appConfig.EventingIngress)...)
	if err != nil {
		log.Panicf("failed to create cloudevents client: %v", err)
	}

	pboidc.RegisterSecurityTokenServiceServer(d.Server, octosts.NewSecurityTokenServiceServer(atr, ceclient, appConfig.Domain, baseCfg.Metrics))
	if err := d.RegisterHandler(ctx, pboidc.RegisterSecurityTokenServiceHandlerFromEndpoint); err != nil {
		log.Panicf("failed to register gateway endpoint: %v", err)
	}

	if err := d.ListenAndServe(ctx); err != nil {
		log.Panicf("ListenAndServe() = %v", err)
	}

	// This will block until a signal arrives.
	<-ctx.Done()
}
