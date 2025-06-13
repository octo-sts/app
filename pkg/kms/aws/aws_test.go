// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReturnsNoError(t *testing.T) {
	signer, err := New(context.Background(), nil, "key")
	assert.NoError(t, err)
	assert.NotNil(t, signer)
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
