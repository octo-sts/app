// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

func GetSecret(ctx context.Context, secretmanager *secretmanager.Client, keyID string) ([]byte, error) {
	resp, err := secretmanager.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("error fetching secret %s: %w", keyID, err)
	}
	return resp.Payload.Data, nil
}
