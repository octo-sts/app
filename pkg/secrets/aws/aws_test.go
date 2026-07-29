// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsSM "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestSMClient(t *testing.T, respBody any) *awsSM.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(respBody)
	}))
	t.Cleanup(srv.Close)

	return awsSM.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
	}, func(o *awsSM.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
	})
}

func TestGetSecret_SecretString(t *testing.T) {
	client := newTestSMClient(t, map[string]string{"SecretString": "my-webhook-secret"})

	got, err := GetSecret(context.Background(), client, "my-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("my-webhook-secret"), got)
}

func TestGetSecret_SecretBinary(t *testing.T) {
	// []byte is base64-encoded by json.Encode, matching AWS's wire format for blob fields.
	client := newTestSMClient(t, map[string]any{"SecretBinary": []byte("binary-secret")})

	got, err := GetSecret(context.Background(), client, "my-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("binary-secret"), got)
}

func TestGetSecret_BothFieldsNil_ReturnsError(t *testing.T) {
	client := newTestSMClient(t, map[string]any{})

	_, err := GetSecret(context.Background(), client, "arn:aws:secretsmanager:us-east-1:123:secret:my-key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no value")
}
