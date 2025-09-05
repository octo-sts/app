// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

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
	key, ok := ikey.(string)
	if !ok {
		return "", fmt.Errorf("invalid key reference type: %T", ikey)
	}
	req := &kmspb.AsymmetricSignRequest{
		Name: key,
		Data: []byte(signingString),
	}
	resp, err := s.client.AsymmetricSign(s.ctx, req)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(resp.Signature), nil
}

func (s *signingMethodGCP) Alg() string {
	return "RS256"
}

type Provider struct {
	ctx    context.Context
	client *kms.KeyManagementClient
	key    string
}

func NewProvider(ctx context.Context, kmsKey string) (*Provider, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Provider{
		ctx:    ctx,
		client: client,
		key:    kmsKey,
	}, nil
}

func (p *Provider) NewSigner() (ghinstallation.Signer, error) {
	return p, nil
}

func (p *Provider) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethodGCP{
		ctx:    p.ctx,
		client: p.client,
	}
	return jwt.NewWithClaims(method, claims).SignedString(p.key)
}
