// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package jwks

import (
	"crypto"
	"encoding/json"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// ConfigOption is a function that modifies the OIDC config.
type ConfigOption func(*oidc.Config)

// NewVerifier creates an OIDC verifier from a JWKS string.
func NewVerifier(raw string, opts ...ConfigOption) (*oidc.IDTokenVerifier, error) {
	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(raw), &jwks); err != nil {
		return nil, err
	}

	var keys []crypto.PublicKey
	for _, key := range jwks.Keys {
		keys = append(keys, key.Key)
	}

	var issuerURL string // ignored
	keySet := &oidc.StaticKeySet{PublicKeys: keys}
	config := &oidc.Config{
		// Issuer and audience are verified later on by the trust policy.
		SkipIssuerCheck:   true,
		SkipClientIDCheck: true,
	}
	for _, opt := range opts {
		opt(config)
	}

	return oidc.NewVerifier(issuerURL, keySet, config), nil
}
