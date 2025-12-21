// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"

	gcpSM "cloud.google.com/go/secretmanager/apiv1"
	"github.com/aws/aws-sdk-go-v2/config"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/octo-sts/app/pkg/secrets/aws"
	"github.com/octo-sts/app/pkg/secrets/gcp"
)

type SecretProvider interface {
	GetSecret(ctx context.Context, keyID string) ([]byte, error)
}

const (
	AWS = "aws"
	GCP = "gcp"
)

type secretProvider struct {
	provider         string
	gcpSecretManager *gcpSM.Client
	awsSecretManager *awsSM.Client
}

func (s *secretProvider) GetSecret(ctx context.Context, keyID string) ([]byte, error) {
	switch s.provider {
	case AWS:
		return aws.GetSecret(ctx, s.awsSecretManager, keyID)
	case GCP:
		return gcp.GetSecret(ctx, s.gcpSecretManager, keyID)
	default:
		return nil, errors.New("unsupported secret provider")
	}
}

func NewSecretProvider(ctx context.Context, provider string) (SecretProvider, error) {
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
	default:
		return nil, errors.New("unsupported secret provider")
	}
}
