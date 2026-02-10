// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func GetSecret(ctx context.Context, manager *awsSM.Client, keyID string) ([]byte, error) {
	req := awsSM.GetSecretValueInput{SecretId: aws.String(keyID)}
	resp, err := manager.GetSecretValue(ctx, &req)
	if err != nil {
		return nil, fmt.Errorf("error fetching secret %s: %w", keyID, err)
	}

	// Depending on how the secret was stored, it can be either a string or binary.
	if resp.SecretString != nil {
		return []byte(*resp.SecretString), nil
	}
	return resp.SecretBinary, nil
}
