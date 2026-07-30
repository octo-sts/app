// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecretProviderReturnsErrOnFakeProvider(t *testing.T) {
	ctx := context.Background()
	_, err := NewSecretProvider(ctx, "fake")
	assert.Error(t, err)
}

func TestSecretProvider_GetSecretReturnsErrOnFakeProvider(t *testing.T) {
	ctx := context.Background()
	sp := &secretProvider{
		provider: "fake",
	}

	val, err := sp.GetSecret(ctx, "fake-key-id")
	assert.Nil(t, val)
	assert.Error(t, err)
}

func TestNewSecretProvider_NormalizesProviderString(t *testing.T) {
	ctx := context.Background()
	// These should all route to a known provider — any error must not be
	// "unsupported secret provider" (cloud SDK init may fail in test envs
	// without credentials, but that's a different error).
	supported := []string{"aws", "AWS", "Aws"}
	for _, input := range supported {
		t.Run(input, func(t *testing.T) {
			_, err := NewSecretProvider(ctx, input)
			if err != nil {
				assert.NotContains(t, err.Error(), "unsupported",
					"provider %q should normalize to a supported value", input)
			}
		})
	}
}

func TestNewSecretProvider_RejectsUnsupportedProvider(t *testing.T) {
	ctx := context.Background()
	_, err := NewSecretProvider(ctx, "unknown-provider")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}
