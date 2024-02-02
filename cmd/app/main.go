package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"

	"chainguard.dev/go-grpc-kit/pkg/duplex"
	pboidc "chainguard.dev/sdk/proto/platform/oidc/v1"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/octo-sts/pkg/gcpkms"
	"github.com/chainguard-dev/octo-sts/pkg/octosts"
	cloudevents "github.com/cloudevents/sdk-go/v2"
	cehttp "github.com/cloudevents/sdk-go/v2/protocol/http"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/api/idtoken"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"knative.dev/pkg/logging"
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

	ceclient, err := cloudevents.NewClientHTTP(WithTarget(ctx, env.EventingIngress)...)
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

// WithTarget wraps cloudevents.WithTarget to authenticate requests with an
// identity token when the target is an HTTPS URL.
func WithTarget(ctx context.Context, url string) []cehttp.Option {
	opts := make([]cehttp.Option, 0, 2)

	if strings.HasPrefix(url, "https://") {
		idc, err := idtoken.NewClient(ctx, url)
		if err != nil {
			logging.FromContext(ctx).Panicf("failed to create idtoken client: %v", err)
		}
		opts = append(opts, cloudevents.WithRoundTripper(idc.Transport))
	}

	opts = append(opts, cehttp.WithTarget(url))
	return opts
}
