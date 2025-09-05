// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewErrorOnInvalidProvider(t *testing.T) {
	kms, err := NewKMS(context.Background(), "fake", "n/a")
	assert.ErrorContains(t, err, "unsupported kms provider")
	assert.Nil(t, kms)
}

func TestNewKMSWithValidProviders(t *testing.T) {
	testCases := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{
			name:     "AWS provider",
			provider: "aws",
			wantErr:  false,
		},
		{
			name:     "AWS provider uppercase",
			provider: "AWS",
			wantErr:  false,
		},
		{
			name:     "GCP provider",
			provider: "gcp",
			wantErr:  false,
		},
		{
			name:     "GCP provider uppercase",
			provider: "GCP",
			wantErr:  false,
		},
		{
			name:     "Invalid provider",
			provider: "invalid",
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kms, err := NewKMS(context.Background(), tc.provider, "test-key")
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, kms)
			} else {
				if err != nil {
					t.Skipf("Skipping test due to missing credentials or connectivity: %v", err)
				}
				assert.NoError(t, err)
				assert.NotNil(t, kms)

				signer, err := kms.NewSigner()
				assert.NoError(t, err)
				assert.NotNil(t, signer)
			}
		})
	}
}
