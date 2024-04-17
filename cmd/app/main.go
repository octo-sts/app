// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"

	"chainguard.dev/go-grpc-kit/pkg/duplex"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	mce "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics/cloudevents"
	"github.com/kelseyhightower/envconfig"
	"github.com/octo-sts/app/pkg/gcpkms"
	"github.com/octo-sts/app/pkg/octosts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type envConfig struct {
	Port            int    `envconfig:"PORT" required:"true"`
	KMSKey          string `envconfig:"KMS_KEY" required:"true"`
	AppID           int64  `envconfig:"GITHUB_APP_ID" required:"true"`
	EventingIngress string `envconfig:"EVENT_INGRESS_URI" required:"true"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	ctx = clog.WithLogger(ctx, clog.New(slog.Default().Handler()))

	go metrics.ServeMetrics()

	// Setup tracing.
	defer metrics.SetupTracer(ctx)()

	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		log.Panicf("failed to process env var: %s", err)
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Panicf("could not create kms client: %v", err)
	}

	signer, err := gcpkms.New(ctx, client, env.KMSKey)
	if err != nil {
		log.Panicf("error creating signer: %v", err)
	}

	atr, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, env.AppID, ghinstallation.WithSigner(signer))
	if err != nil {
		log.Panicf("error creating GitHub App transport: %v", err)
	}

	d := duplex.New(
		env.Port,
		// grpc.StatsHandler(otelgrpc.NewServerHandler()),
		// grpc.ChainStreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		// grpc.ChainUnaryInterceptor(grpc_prometheus.UnaryServerInterceptor, interceptors.ServerErrorInterceptor),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	ceclient, err := mce.NewClientHTTP(mce.WithTarget(ctx, env.EventingIngress)...)
	if err != nil {
		log.Panicf("failed to create cloudevents client: %v", err)
	}

	pboidc.RegisterSecurityTokenServiceServer(d.Server, octosts.NewSecurityTokenServiceServer(atr, ceclient))
	if err := d.RegisterHandler(ctx, pboidc.RegisterSecurityTokenServiceHandlerFromEndpoint); err != nil {
		log.Panicf("failed to register gateway endpoint: %v", err)
	}

	if err := d.ListenAndServe(ctx); err != nil {
		log.Panicf("ListenAndServe() = %v", err)
	}

	// This will block until a signal arrives.
	<-ctx.Done()
}
