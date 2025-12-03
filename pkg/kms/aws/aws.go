// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

type signingMethodAWS struct {
	ctx    context.Context
	client *kms.Client
}

func (s *signingMethodAWS) Verify(signingString, signature string, key interface{}) error {
	return errors.New("not implemented")
}

func (s *signingMethodAWS) Sign(signingString string, ikey interface{}) (string, error) {
	key, ok := ikey.(string)
	if !ok {
		return "", fmt.Errorf("invalid key reference type: %T", ikey)
	}
	resp, err := s.client.Sign(s.ctx, &kms.SignInput{
		KeyId:            aws.String(key),
		Message:          []byte(signingString),
		MessageType:      types.MessageTypeRaw,
		SigningAlgorithm: types.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(resp.Signature), nil
}

func (s *signingMethodAWS) Alg() string {
	return "RS256"
}

type Provider struct {
	ctx    context.Context
	client *kms.Client
	key    string
}

func NewProvider(ctx context.Context, kmsKey string) (*Provider, error) {
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	client := kms.NewFromConfig(awsConfig)

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
	method := &signingMethodAWS{
		ctx:    p.ctx,
		client: p.client,
	}
	return jwt.NewWithClaims(method, claims).SignedString(p.key)
}
