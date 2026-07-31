// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package akv

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/chainguard-dev/clog"
	"github.com/octo-sts/app/pkg/internal/akverr"
)

// ParseSecretID validates a Key Vault secret identifier and returns the vault
// URL it points at. Identifiers have the form
// https://<vault>/secrets/<name>[/<version>], where <vault> may be either a
// Key Vault or a Managed HSM host. The path check also keeps azsecrets.ID
// safe to use, since its Name accessor dereferences a nil pointer when the
// path has fewer than two segments.
func ParseSecretID(secretID string) (string, error) {
	u, err := url.Parse(secretID)
	if err != nil || u.Scheme != "https" || u.Host == "" ||
		!strings.HasPrefix(strings.ToLower(u.Path), "/secrets/") {
		return "", fmt.Errorf("invalid Key Vault secret identifier %q: want https://<vault>/secrets/<name>[/<version>]", secretID)
	}

	id := azsecrets.ID(secretID)
	if id.Name() == "" {
		return "", fmt.Errorf("invalid Key Vault secret identifier %q: missing secret name", secretID)
	}

	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

func GetSecret(ctx context.Context, client *azsecrets.Client, keyID string) ([]byte, error) {
	if _, err := ParseSecretID(keyID); err != nil {
		return nil, err
	}

	id := azsecrets.ID(keyID)

	resp, err := client.GetSecret(ctx, id.Name(), id.Version(), nil)
	if err != nil {
		// Log the full Azure error (including the vault host and secret name)
		// to the structured logger, which is IAM-protected. The returned error
		// is sanitized so those identifiers never propagate to callers.
		clog.ErrorContextf(ctx, "keyvault GetSecret %s: %v", id.Name(), err)
		return nil, fmt.Errorf("error fetching secret: %w", akverr.Sanitize(err))
	}

	if resp.Value == nil || *resp.Value == "" {
		return nil, fmt.Errorf("secret does not exist")
	}
	return []byte(*resp.Value), nil
}
