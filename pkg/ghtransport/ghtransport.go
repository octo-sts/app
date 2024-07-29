// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"context"
	"log"
	"net/http"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/gcpkms"
)

func New(ctx context.Context, env *envConfig.EnvConfig, kmsClient *kms.KeyManagementClient) (*ghinstallation.AppsTransport, error) {
	switch {
	case env.AppSecretCertificateEnvVar != "":
		atr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, env.AppID, []byte(env.AppSecretCertificateEnvVar))

		if err != nil {
			log.Panicf("error creating GitHub App transport: %v", err)
		}
		return atr, nil

	case env.AppSecretCertificateFile != "":
		atr, err := ghinstallation.NewAppsTransportKeyFromFile(http.DefaultTransport, env.AppID, env.AppSecretCertificateFile)

		if err != nil {
			log.Panicf("error creating GitHub App transport: %v", err)
		}
		return atr, nil
	default:
		if env.KMSKey == "" {
			log.Panicf("failed to process env var: %s", env.KMSKey)
		}

		signer, err := gcpkms.New(ctx, kmsClient, env.KMSKey)
		if err != nil {
			log.Panicf("error creating signer: %v", err)
		}

		atr, err := ghinstallation.NewAppsTransportWithOptions(http.DefaultTransport, env.AppID, ghinstallation.WithSigner(signer))
		if err != nil {
			log.Panicf("error creating GitHub App transport: %v", err)
		}

		return atr, nil
	}
}
