// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"net"
	"testing"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/golang-jwt/jwt/v4"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type fakeGCPKMS struct {
	kmspb.UnimplementedKeyManagementServiceServer
}

func (fakeGCPKMS) AsymmetricSign(context.Context, *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	return &kmspb.AsymmetricSignResponse{
		Signature: []byte("fake"),
	}, nil
}

func TestGCP(t *testing.T) {
	ctx := context.Background()

	// Setup the fake server.
	impl := &fakeGCPKMS{}
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	gsrv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(gsrv, impl)
	fakeServerAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err)
		}
	}()

	// Create a client.
	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(fakeServerAddr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := New(ctx, client, "foo")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := signer.Sign(jwt.RegisteredClaims{
		Subject: "foo",
		Issuer:  "bar",
	}); err != nil {
		t.Fatal(err)
	}
}
