// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewErrorOnInvalidProvider(t *testing.T) {
	kms, err := NewKMS(context.Background(), "fake", "n/a")
	assert.ErrorContains(t, err, "unsupported kms provider")
	assert.Nil(t, kms)
}

func TestNewKMSWithValidProviders(t *testing.T) {
	const akvKey = "https://vault-a.vault.azure.net/keys/signing-key"

	testCases := []struct {
		name     string
		provider string
		key      string
		wantErr  bool
		// offlineConstruct marks providers whose client is built without
		// contacting the cloud, so construction has no environmental reason
		// to fail and the assertion can be unconditional.
		offlineConstruct bool
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
			name:             "AKV provider",
			provider:         "akv",
			key:              akvKey,
			wantErr:          false,
			offlineConstruct: true,
		},
		{
			name:             "AKV provider uppercase",
			provider:         "AKV",
			key:              akvKey,
			wantErr:          false,
			offlineConstruct: true,
		},
		{
			name:     "Invalid provider",
			provider: "invalid",
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := tc.key
			if key == "" {
				key = "test-key"
			}
			kms, err := NewKMS(context.Background(), tc.provider, key)
			if tc.wantErr {
				assert.Error(t, err)
				assert.Nil(t, kms)
				return
			}

			// A routing regression must never be mistaken for a missing
			// credential: if the factory stopped dispatching this provider,
			// fail loudly instead of skipping.
			if err != nil {
				require.NotContains(t, err.Error(), "unsupported kms provider",
					"provider %q is supported but was not routed by NewKMS", tc.provider)
			}

			// Providers that build their client offline have no environmental
			// excuse, so assert unconditionally. The rest may legitimately fail
			// in a test environment without cloud credentials.
			if !tc.offlineConstruct && err != nil {
				t.Skipf("Skipping test due to missing credentials or connectivity: %v", err)
			}

			require.NoError(t, err)
			assert.NotNil(t, kms)
		})
	}
}

func TestNewKMSRejectsMalformedAKVKey(t *testing.T) {
	// AKV parses the key identifier up front, so a bad value must surface as
	// an error here rather than at first sign.
	for _, key := range []string{
		"signing-key",
		"https://vault-a.vault.azure.net",
		"arn:aws:kms:us-east-1:123:key/abcd",
	} {
		t.Run(key, func(t *testing.T) {
			got, err := NewKMS(context.Background(), AKV, key)
			assert.Error(t, err)
			assert.Nil(t, got)
		})
	}
}
