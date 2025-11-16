// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"errors"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/octo-sts/app/pkg/kms/aws"
	"github.com/octo-sts/app/pkg/kms/gcp"
)

const (
	AWS = "aws"
	GCP = "gcp"
)

type KMS interface {
	NewSigner() (ghinstallation.Signer, error)
}

func NewKMS(ctx context.Context, provider, kmsKey string) (KMS, error) {
	switch strings.ToLower(provider) {
	case GCP:
		return gcp.NewProvider(ctx, kmsKey)
	case AWS:
		return aws.NewProvider(ctx, kmsKey)
	default:
		return nil, errors.New("unsupported kms provider")
	}
}
