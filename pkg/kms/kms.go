// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/octo-sts/app/pkg/kms/akv"
	"github.com/octo-sts/app/pkg/kms/aws"
	"github.com/octo-sts/app/pkg/kms/gcp"
)

const (
	AWS = "aws"
	GCP = "gcp"
	AKV = "akv"
)

// KMS is a JWT signer backed by a cloud KMS. Callers should Close it at
// shutdown to release any underlying client connections.
type KMS interface {
	ghinstallation.Signer
	io.Closer
}

func NewKMS(ctx context.Context, provider, kmsKey string) (KMS, error) {
	switch strings.ToLower(provider) {
	case GCP:
		return gcp.NewProvider(ctx, kmsKey)
	case AWS:
		return aws.NewProvider(ctx, kmsKey)
	case AKV:
		return akv.NewProvider(ctx, kmsKey)
	default:
		return nil, errors.New("unsupported kms provider")
	}
}
