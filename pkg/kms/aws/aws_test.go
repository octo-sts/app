// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewProviderReturnsProvider(t *testing.T) {
	provider, err := NewProvider(context.Background(), "test-key")
	if err != nil {
		t.Skipf("Skipping test due to missing AWS credentials or connectivity: %v", err)
	}
	assert.NoError(t, err)
	assert.NotNil(t, provider)

	signer, err := provider.NewSigner()
	assert.NoError(t, err)
	assert.NotNil(t, signer)
	assert.Equal(t, provider, signer)
}

func TestSigningMethodAWS_AlgIsRS256(t *testing.T) {
	method := &signingMethodAWS{}
	assert.Equal(t, method.Alg(), "RS256")
}

func TestSigningMethodAWS_Verify_NotImplemented(t *testing.T) {
	method := &signingMethodAWS{}
	err := method.Verify("string", "signature", "key")
	assert.ErrorContains(t, err, "not implemented")
}
