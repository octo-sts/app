// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/chainguard-dev/clog"
	"github.com/octo-sts/app/pkg/internal/awserr"
)

func GetSecret(ctx context.Context, manager *awsSM.Client, keyID string) ([]byte, error) {
	req := awsSM.GetSecretValueInput{SecretId: aws.String(keyID)}
	resp, err := manager.GetSecretValue(ctx, &req)
	if err != nil {
		// Log the full AWS error (including resource ARN) to the structured
		// logger, which goes to Cloud Logging and is IAM-protected.  The
		// returned error is sanitized so ARNs never propagate to callers.
		clog.ErrorContextf(ctx, "secretsmanager GetSecretValue %s: %v", keyID, err)
		return nil, fmt.Errorf("error fetching secret: %w", awserr.Sanitize(err))
	}

	// Depending on how the secret was stored, it can be either a string or binary.
	if resp.SecretString != nil {
		return []byte(*resp.SecretString), nil
	}
	if resp.SecretBinary == nil {
		return nil, fmt.Errorf("secret has no value")
	}
	return resp.SecretBinary, nil
}
