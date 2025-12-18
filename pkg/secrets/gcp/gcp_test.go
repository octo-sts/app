// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"net"
	"testing"

	"cloud.google.com/go/iam/apiv1/iampb"
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestReturnsSecretDataWithValidKeyID(t *testing.T) {
	ctx := context.Background()

	// Set up the fake server.
	impl := &fakeSecretManager{}
	l, err := net.Listen("tcp", "localhost:0")
	assert.NoError(t, err)
	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, impl)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			t.Fatal(err)
		}
	}()
	defer gsrv.Stop()

	// Create a client.
	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	assert.NoError(t, err)

	data, err := GetSecret(ctx, client, "projects/foo/secrets/bar/versions/latest")
	assert.NoError(t, err)
	assert.Equal(t, "fake-secret-data", string(data))
}

func TestFailsToFetchSecretWithInvalidKeyID(t *testing.T) {
	ctx := context.Background()

	// Set up the fake server.
	impl := &fakeSecretManager{}
	l, err := net.Listen("tcp", "localhost:0")
	assert.NoError(t, err)

	gsrv := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gsrv, impl)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()
	defer gsrv.Stop()

	// Create a client.
	client, err := secretmanager.NewClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	assert.NoError(t, err)

	_, err = GetSecret(ctx, client, "invalid-key-id")
	assert.Error(t, err)
}

// Implement interface methods for the fake server.
type fakeSecretManager struct {
  secretmanagerpb.UnimplementedSecretManagerServiceServer
}

func (f fakeSecretManager) ListSecrets(ctx context.Context, request *secretmanagerpb.ListSecretsRequest) (*secretmanagerpb.ListSecretsResponse, error) {
	panic("implement me")
}

func (f fakeSecretManager) CreateSecret(ctx context.Context, request *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
	panic("implement me")
}

func (f fakeSecretManager) AddSecretVersion(ctx context.Context, request *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	panic("implement me")
}

func (f fakeSecretManager) GetSecret(ctx context.Context, request *secretmanagerpb.GetSecretRequest) (*secretmanagerpb.Secret, error) {
	panic("implement me")
}

func (f fakeSecretManager) UpdateSecret(ctx context.Context, request *secretmanagerpb.UpdateSecretRequest) (*secretmanagerpb.Secret, error) {
	panic("implement me")
}

func (f fakeSecretManager) DeleteSecret(ctx context.Context, request *secretmanagerpb.DeleteSecretRequest) (*emptypb.Empty, error) {
	panic("implement me")
}

func (f fakeSecretManager) ListSecretVersions(ctx context.Context, request *secretmanagerpb.ListSecretVersionsRequest) (*secretmanagerpb.ListSecretVersionsResponse, error) {
	panic("implement me")
}

func (f fakeSecretManager) GetSecretVersion(ctx context.Context, request *secretmanagerpb.GetSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	panic("implement me")
}

func (f fakeSecretManager) AccessSecretVersion(ctx context.Context, request *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if request.Name == "projects/foo/secrets/bar/versions/latest" {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Payload: &secretmanagerpb.SecretPayload{
				Data: []byte("fake-secret-data"),
			},
		}, nil
	}
	return nil, errors.New("not found")
}

func (f fakeSecretManager) DisableSecretVersion(ctx context.Context, request *secretmanagerpb.DisableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	panic("implement me")
}

func (f fakeSecretManager) EnableSecretVersion(ctx context.Context, request *secretmanagerpb.EnableSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	panic("implement me")
}

func (f fakeSecretManager) DestroySecretVersion(ctx context.Context, request *secretmanagerpb.DestroySecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
	panic("implement me")
}

func (f fakeSecretManager) SetIamPolicy(ctx context.Context, request *iampb.SetIamPolicyRequest) (*iampb.Policy, error) {
	panic("implement me")
}

func (f fakeSecretManager) GetIamPolicy(ctx context.Context, request *iampb.GetIamPolicyRequest) (*iampb.Policy, error) {
	panic("implement me")
}

func (f fakeSecretManager) TestIamPermissions(ctx context.Context, request *iampb.TestIamPermissionsRequest) (*iampb.TestIamPermissionsResponse, error) {
	panic("implement me")
}
