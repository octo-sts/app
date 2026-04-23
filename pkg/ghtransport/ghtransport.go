// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"context"
	"fmt"
	"net/http"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/gcpkms"
)

// EnrichContext adds GitHub App and installation ID values to the context so
// that the httpmetrics transport can label rate-limit metrics with the specific
// installation consuming quota.
func EnrichContext(ctx context.Context, appID, installationID int64) context.Context {
	ctx = metrics.WithGitHubAppID(ctx, appID)
	ctx = metrics.WithGitHubInstallationID(ctx, installationID)
	return ctx
}

func New(ctx context.Context, appID int64, kmsKey string, env *envConfig.EnvConfig, kmsClient *kms.KeyManagementClient) (*ghinstallation.AppsTransport, error) {
	switch {
	case env.AppSecretCertificateEnvVar != "":
		atr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, []byte(env.AppSecretCertificateEnvVar))

		if err != nil {
			return nil, err
		}
		return atr, nil

	case env.AppSecretCertificateFile != "":
		atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, appID, env.AppSecretCertificateFile)

		if err != nil {
			return nil, err
		}
		return atr, nil
	default:
		if kmsKey == "" {
			return nil, fmt.Errorf("no KMS key provided for app %d", appID)
		}

		signer, err := gcpkms.New(ctx, kmsClient, kmsKey)
		if err != nil {
			return nil, fmt.Errorf("error creating signer: %w", err)
		}

		atr, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, appID, ghinstallation.WithSigner(signer))
		if err != nil {
			return nil, err
		}

		return atr, nil
	}
}
