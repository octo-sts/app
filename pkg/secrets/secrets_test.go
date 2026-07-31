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

func TestNewSecretProvider_AKV(t *testing.T) {
	ctx := context.Background()

	t.Run("valid secret identifier", func(t *testing.T) {
		// The AKV vault URL is derived from the webhook secret identifier.
		t.Setenv("GITHUB_WEBHOOK_SECRET", "https://vault-a.vault.azure.net/secrets/webhook-secret")

		sp, err := NewSecretProvider(ctx, "akv")
		require.NoError(t, err)
		assert.NotNil(t, sp)
	})

	t.Run("normalizes provider casing", func(t *testing.T) {
		t.Setenv("GITHUB_WEBHOOK_SECRET", "https://vault-a.vault.azure.net/secrets/webhook-secret")

		sp, err := NewSecretProvider(ctx, "AKV")
		require.NoError(t, err)
		assert.NotNil(t, sp)
	})

	t.Run("rejects malformed secret identifier", func(t *testing.T) {
		for _, secret := range []string{
			"webhook-secret",                             // bare name
			"https://vault-a.vault.azure.net",            // no /secrets/ path
			"http://vault-a.vault.azure.net/secrets/foo", // not https
		} {
			t.Run(secret, func(t *testing.T) {
				t.Setenv("GITHUB_WEBHOOK_SECRET", secret)

				sp, err := NewSecretProvider(ctx, "akv")
				require.Error(t, err)
				assert.Nil(t, sp)
			})
		}
	})
}

func TestNewSecretProvider_AKVMultipleSecrets(t *testing.T) {
	ctx := context.Background()
	const vault = "https://vault-a.vault.azure.net"

	t.Run("accepts several secrets in one vault", func(t *testing.T) {
		t.Setenv("GITHUB_WEBHOOK_SECRET", vault+"/secrets/current,"+vault+"/secrets/previous")

		sp, err := NewSecretProvider(ctx, "akv")
		require.NoError(t, err)
		assert.NotNil(t, sp)
	})

	t.Run("tolerates whitespace between entries", func(t *testing.T) {
		t.Setenv("GITHUB_WEBHOOK_SECRET", vault+"/secrets/current, "+vault+"/secrets/previous")

		sp, err := NewSecretProvider(ctx, "akv")
		require.NoError(t, err)
		assert.NotNil(t, sp)
	})

	t.Run("rejects secrets spread across vaults", func(t *testing.T) {
		// One client is bound to one vault, so a mixed list must fail loudly
		// rather than read every secret from the first vault.
		t.Setenv("GITHUB_WEBHOOK_SECRET",
			vault+"/secrets/current,https://vault-b.vault.azure.net/secrets/previous")

		sp, err := NewSecretProvider(ctx, "akv")
		require.Error(t, err)
		assert.Nil(t, sp)
		assert.Contains(t, err.Error(), "same vault")
	})

	t.Run("rejects when any entry is malformed", func(t *testing.T) {
		// The second entry is a bare name, which would previously be hidden
		// inside the first entry's URL path.
		t.Setenv("GITHUB_WEBHOOK_SECRET", vault+"/secrets/current,previous")

		sp, err := NewSecretProvider(ctx, "akv")
		require.Error(t, err)
		assert.Nil(t, sp)
		assert.Contains(t, err.Error(), "secret identifier")
	})
}
