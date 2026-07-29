// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
)

func GetSecret(ctx context.Context, manager *awsSM.Client, keyID string) ([]byte, error) {
	req := awsSM.GetSecretValueInput{SecretId: aws.String(keyID)}
	resp, err := manager.GetSecretValue(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("error fetching secret: %w", sanitizeAWSError(err))
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

// sanitizeAWSError replaces an AWS SDK error with one that contains only the
// error code, stripping the message which may contain resource ARNs and AWS
// account identifiers.
func sanitizeAWSError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s", apiErr.ErrorCode()) //nolint:err113
	}
	return err
}
