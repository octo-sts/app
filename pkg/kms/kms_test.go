// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"net"
	"testing"

	gcpKMS "cloud.google.com/go/kms/apiv1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestNewErrorOnInvalidProvider(t *testing.T) {
	kms, err := NewKMS(context.Background(), "fake", "n/a")
	assert.ErrorContains(t, err, "unsupported kms provider")
	assert.Nil(t, kms)
}

func TestKmsProvider_NewSignerForGCP(t *testing.T) {
	kms := &kmsProvider{
		provider:  "gcp",
		ctx:       context.Background(),
		kmsKey:    "n/a",
		gcpClient: generateKMSClient(context.Background(), t),
	}

	signer, err := kms.NewSigner()
	assert.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestKmsProvider_NewSignerReturnsError(t *testing.T) {
	kms := &kmsProvider{
		provider: "fake",
		ctx:      context.Background(),
		kmsKey:   "n/a",
	}
	signer, err := kms.NewSigner()
	assert.ErrorContains(t, err, "unsupported kms provider")
	assert.Nil(t, signer)
}

func generateKMSClient(ctx context.Context, t *testing.T) *gcpKMS.KeyManagementClient {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	fakeServerAddr := l.Addr().String()

	client, err := gcpKMS.NewKeyManagementClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}

	return client
}
