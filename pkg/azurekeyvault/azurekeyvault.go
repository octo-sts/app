// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

const signatureAlg = azkeys.SignatureAlgorithmRS256

// signerClient is the subset of *azkeys.Client used for signing. It exists so
// tests can inject a fake without contacting Azure. *azkeys.Client satisfies it.
type signerClient interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
}

var _ signerClient = (*azkeys.Client)(nil)

type keyRef struct {
	name    string
	version string
}

type signingMethodAKV struct {
	client signerClient
	// Storing a context on a struct is discouraged by Go, but the jwt
	// SigningMethod interface has no parameter to pass one, so we carry it
	// here to propagate shutdown cancellation to the sign call.
	ctx context.Context
}

func (s *signingMethodAKV) Verify(string, string, interface{}) error {
	return errors.New("not implemented")
}

func (s *signingMethodAKV) Sign(signingString string, ikey interface{}) (string, error) {
	ref, ok := ikey.(keyRef)

	if !ok {
		return "", fmt.Errorf("invalid key reference type: %T", ikey)
	}

	digest := sha256.Sum256([]byte(signingString))

	alg := signatureAlg

	resp, err := s.client.Sign(s.ctx, ref.name, ref.version, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest[:],
	}, nil)

	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(resp.Result), nil
}

func (s *signingMethodAKV) Alg() string { return string(signatureAlg) }

type akvSigner struct {
	client signerClient
	key    keyRef
	// Storing a context on a struct is discouraged by Go, but the jwt
	// SigningMethod interface has no parameter to pass one, so we carry it
	// here to propagate shutdown cancellation to the sign call.
	ctx context.Context
}

func (s *akvSigner) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethodAKV{client: s.client, ctx: s.ctx}
	return jwt.NewWithClaims(method, claims).SignedString(s.key)
}

func New(ctx context.Context, vaultURL, keyName, keyVersion string) (ghinstallation.Signer, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)

	if err != nil {
		return nil, fmt.Errorf("could not create az credential: %w", err)
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)

	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	return &akvSigner{
		client: client,
		key:    keyRef{name: keyName, version: keyVersion},
		ctx:    ctx,
	}, nil
}
