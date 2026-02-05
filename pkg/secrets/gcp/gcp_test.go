// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"net"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func setupFakeSecretManagerClient(t *testing.T) *secretmanager.Client {
	t.Helper()
	ctx := context.Background()

	// Set up the fake server.
	impl := &fakeSecretManager{}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, impl)
	fakeServerAddr := l.Addr().String()

	go gsrv.Serve(l) //nolint:errcheck

	t.Cleanup(func() {
		gsrv.Stop()
	})

	// Create a client.
	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestReturnsSecretDataWithValidKeyID(t *testing.T) {
	ctx := context.Background()
	client := setupFakeSecretManagerClient(t)

	data, err := GetSecret(ctx, client, "projects/foo/secrets/bar/versions/latest")
	assert.NoError(t, err)
	assert.Equal(t, "fake-secret-data", string(data))
}

func TestFailsToFetchSecretWithInvalidKeyID(t *testing.T) {
	ctx := context.Background()
	client := setupFakeSecretManagerClient(t)

	_, err := GetSecret(ctx, client, "invalid-key-id")
	assert.Error(t, err)
}

// fakeSecretManager implements the SecretManagerServiceServer interface.
// By embedding UnimplementedSecretManagerServiceServer, we only need to
// implement the methods we actually use in tests.
type fakeSecretManager struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (f fakeSecretManager) AccessSecretVersion(_ context.Context, request *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if request.Name == "projects/foo/secrets/bar/versions/latest" {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Payload: &secretmanagerpb.SecretPayload{
				Data: []byte("fake-secret-data"),
			},
		}, nil
	}
	return nil, errors.New("not found")
}
