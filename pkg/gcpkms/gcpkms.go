// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcpkms

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

type signingMethodGCP struct {
	ctx    context.Context
	client *kms.KeyManagementClient
}

func (s *signingMethodGCP) Verify(string, string, interface{}) error {
	return errors.New("not implemented")
}

func (s *signingMethodGCP) Sign(signingString string, ikey interface{}) (string, error) {
	ctx := s.ctx

	key, ok := ikey.(string)
	if !ok {
		return "", fmt.Errorf("invalid key reference type: %T", ikey)
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: key,
		Data: []byte(signingString),
	}
	resp, err := s.client.AsymmetricSign(ctx, req)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(resp.Signature), nil
}

func (s *signingMethodGCP) Alg() string {
	return "RS256"
}

type gcpSigner struct {
	ctx    context.Context
	client *kms.KeyManagementClient
	key    string
}

func New(ctx context.Context, client *kms.KeyManagementClient, key string) (ghinstallation.Signer, error) {
	return &gcpSigner{
		ctx:    ctx,
		client: client,
		key:    key,
	}, nil
}

// Sign signs the JWT claims with the RSA key.
func (s *gcpSigner) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethodGCP{
		ctx:    s.ctx,
		client: s.client,
	}
	return jwt.NewWithClaims(method, claims).SignedString(s.key)
}
