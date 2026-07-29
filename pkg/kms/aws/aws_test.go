// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestKMSClient(t *testing.T, handler http.HandlerFunc) *kms.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return kms.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
	}, func(o *kms.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
	})
}

func TestNewProviderReturnsProvider(t *testing.T) {
	provider, err := NewProvider(context.Background(), "test-key")
	if err != nil {
		t.Skipf("Skipping test due to missing AWS credentials or connectivity: %v", err)
	}
	assert.NoError(t, err)
	assert.NotNil(t, provider)
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

func TestProviderSign_ReturnsBase64URLSignature(t *testing.T) {
	rawSig := []byte("fake-kms-signature-bytes")
	client := newTestKMSClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		// The AWS SDK base64-decodes the JSON blob field back into []byte.
		_ = json.NewEncoder(w).Encode(map[string]any{"Signature": rawSig})
	})

	p := &Provider{ctx: context.Background(), client: client, key: "test-key"}
	token, err := p.Sign(jwt.RegisteredClaims{Subject: "foo", Issuer: "bar"})
	require.NoError(t, err)

	// The JWT signature segment must be the base64url encoding of the raw
	// bytes KMS returned.
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(rawSig), parts[2])
}

func TestProviderSign_APIError_IsSanitized(t *testing.T) {
	sensitiveARN := "arn:aws:kms:us-east-1:123456789012:key/abcd-ef01"
	client := newTestKMSClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("X-Amzn-Errortype", "AccessDeniedException")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"__type":  "AccessDeniedException",
			"message": "User is not authorized to perform kms:Sign on " + sensitiveARN,
		})
	})

	p := &Provider{ctx: context.Background(), client: client, key: sensitiveARN}
	_, err := p.Sign(jwt.RegisteredClaims{Subject: "foo"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AccessDeniedException")
	// The ARN and account ID must not leak into the returned error.
	assert.NotContains(t, err.Error(), sensitiveARN)
	assert.NotContains(t, err.Error(), "123456789012")
}

func TestProviderSign_InvalidKeyType(t *testing.T) {
	method := &signingMethodAWS{ctx: context.Background()}
	_, err := method.Sign("signing-string", 12345)
	assert.ErrorContains(t, err, "invalid key reference type")
}

func TestProviderClose_NoError(t *testing.T) {
	p := &Provider{ctx: context.Background()}
	assert.NoError(t, p.Close())
}
