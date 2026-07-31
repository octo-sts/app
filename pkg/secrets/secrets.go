// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"

	gcpSM "cloud.google.com/go/secretmanager/apiv1"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/config"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/secrets/akv"
	"github.com/octo-sts/app/pkg/secrets/aws"
	"github.com/octo-sts/app/pkg/secrets/gcp"
)

type SecretProvider interface {
	GetSecret(ctx context.Context, keyID string) ([]byte, error)
}

const (
	AWS = "aws"
	GCP = "gcp"
	AKV = "akv"
)

type secretProvider struct {
	provider         string
	gcpSecretManager *gcpSM.Client
	awsSecretManager *awsSM.Client
	akvSecretManager *azsecrets.Client
}

func (s *secretProvider) GetSecret(ctx context.Context, keyID string) ([]byte, error) {
	switch s.provider {
	case AWS:
		return aws.GetSecret(ctx, s.awsSecretManager, keyID)
	case GCP:
		return gcp.GetSecret(ctx, s.gcpSecretManager, keyID)
	case AKV:
		return akv.GetSecret(ctx, s.akvSecretManager, keyID)
	default:
		return nil, errors.New("unsupported secret provider")
	}
}

func NewSecretProvider(ctx context.Context, provider string) (SecretProvider, error) {
	provider = strings.ToLower(provider)
	sp := &secretProvider{
		provider: provider,
	}

	switch provider {
	case AWS:
		awsConfig, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		client := awsSM.NewFromConfig(awsConfig)
		sp.awsSecretManager = client
		return sp, nil
	case GCP:
		client, err := gcpSM.NewClient(ctx)
		if err != nil {
			return nil, err
		}
		sp.gcpSecretManager = client
		return sp, nil
	case AKV:
		cfg, err := envconfig.WebhookConfig()
		if err != nil {
			return nil, err
		}

		// GITHUB_WEBHOOK_SECRET is a comma-separated list, so validate each
		// entry rather than the joined string: commas are legal in a URL path,
		// so parsing the whole value would silently swallow every entry after
		// the first and derive the vault from only the leading one.
		var vaultURL string
		for _, entry := range strings.Split(cfg.WebhookSecret, ",") {
			entry = strings.TrimSpace(entry)
			v, err := akv.ParseSecretID(entry)
			if err != nil {
				return nil, err
			}
			// One client is bound to one vault, so reject a mixed set instead
			// of silently reading every secret from the first vault.
			if vaultURL == "" {
				vaultURL = v
			} else if !strings.EqualFold(vaultURL, v) {
				return nil, fmt.Errorf("all GITHUB_WEBHOOK_SECRET entries must be in the same vault: found %s and %s", vaultURL, v)
			}
		}

		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("failed to obtain a credential: %w", err)
		}
		client, err := azsecrets.NewClient(vaultURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("could not create client: %w", err)
		}
		sp.akvSecretManager = client
		return sp, nil

	default:
		return nil, errors.New("unsupported secret provider")
	}
}
