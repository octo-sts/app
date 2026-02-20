// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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
