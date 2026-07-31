// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package akv

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/chainguard-dev/clog"
	"github.com/golang-jwt/jwt/v4"
	"github.com/octo-sts/app/pkg/internal/akverr"
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
	ctx    context.Context
	client signerClient
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
		// Log the full Azure error (which embeds the vault host, key name and
		// response body) to the structured logger, which is IAM-protected. The
		// returned error is sanitized so those identifiers never reach callers.
		clog.ErrorContextf(s.ctx, "keyvault Sign %s: %v", ref.name, err)
		return "", fmt.Errorf("keyvault sign: %w", akverr.Sanitize(err))
	}

	return base64.RawURLEncoding.EncodeToString(resp.Result), nil
}

func (s *signingMethodAKV) Alg() string { return string(signatureAlg) }

type Provider struct {
	ctx    context.Context
	client signerClient
	key    keyRef
}

func NewProvider(ctx context.Context, kmsKey string) (*Provider, error) {
	u, err := url.Parse(kmsKey)
	if err != nil || u.Scheme != "https" || u.Host == "" ||
		!strings.HasPrefix(strings.ToLower(u.Path), "/keys/") {
		return nil, fmt.Errorf("invalid Key Vault key identifier %q: want https://<vault>/keys/<name>[/<version>]", kmsKey)
	}

	id := azkeys.ID(kmsKey)
	if id.Name() == "" {
		return nil, fmt.Errorf("invalid Key Vault key identifier %q: missing key name", kmsKey)
	}

	vaultURL := fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	cred, err := azidentity.NewDefaultAzureCredential(nil)

	if err != nil {
		return nil, fmt.Errorf("could not create az credential: %w", err)
	}

	client, err := azkeys.NewClient(vaultURL, cred, nil)

	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	return &Provider{
		client: client,
		key:    keyRef{name: id.Name(), version: id.Version()},
		ctx:    context.WithoutCancel(ctx),
	}, nil
}

func (p *Provider) Sign(claims jwt.Claims) (string, error) {
	method := &signingMethodAKV{client: p.client, ctx: p.ctx}
	return jwt.NewWithClaims(method, claims).SignedString(p.key)
}

func (p *Provider) Close() error { return nil }
