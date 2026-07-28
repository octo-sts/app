// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package azurekeyvault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/golang-jwt/jwt/v4"
)

// fakeKV is a stand-in for *azkeys.Client that records the request and returns
// a canned signature, so tests never contact Azure.
type fakeKV struct {
	gotName    string
	gotVersion string
	gotParams  azkeys.SignParameters
	result     []byte
	err        error
}

func (f *fakeKV) Sign(_ context.Context, name, version string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.gotName = name
	f.gotVersion = version
	f.gotParams = params
	if f.err != nil {
		return azkeys.SignResponse{}, f.err
	}
	return azkeys.SignResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: f.result},
	}, nil
}

func TestSigningMethodSign(t *testing.T) {
	rawSig := []byte("fake-signature-bytes")
	fake := &fakeKV{result: rawSig}
	method := &signingMethodAKV{client: fake}

	signingString := "header.payload"
	got, err := method.Sign(signingString, keyRef{name: "my-key", version: "v1"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// Signature is returned base64url-encoded without padding.
	if want := base64.RawURLEncoding.EncodeToString(rawSig); got != want {
		t.Errorf("signature = %q, want %q", got, want)
	}

	// Key name and version are forwarded to Key Vault.
	if fake.gotName != "my-key" || fake.gotVersion != "v1" {
		t.Errorf("forwarded name/version = %q/%q, want my-key/v1", fake.gotName, fake.gotVersion)
	}

	// RS256 algorithm is requested.
	if fake.gotParams.Algorithm == nil || *fake.gotParams.Algorithm != azkeys.SignatureAlgorithmRS256 {
		t.Errorf("algorithm = %v, want RS256", fake.gotParams.Algorithm)
	}

	// The signing string is SHA-256 hashed before being sent.
	wantDigest := sha256.Sum256([]byte(signingString))
	if string(fake.gotParams.Value) != string(wantDigest[:]) {
		t.Errorf("digest sent to Key Vault does not match sha256(signingString)")
	}
}

func TestSigningMethodSignEmptyVersion(t *testing.T) {
	fake := &fakeKV{result: []byte("sig")}
	method := &signingMethodAKV{client: fake}

	if _, err := method.Sign("a.b", keyRef{name: "my-key"}); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if fake.gotVersion != "" {
		t.Errorf("version = %q, want empty (latest)", fake.gotVersion)
	}
}

func TestSigningMethodSignBadKeyType(t *testing.T) {
	method := &signingMethodAKV{client: &fakeKV{}}

	if _, err := method.Sign("a.b", "not-a-keyRef"); err == nil {
		t.Fatal("expected error for invalid key reference type, got nil")
	}
}

func TestSigningMethodSignPropagatesError(t *testing.T) {
	fake := &fakeKV{err: errors.New("key vault boom")}
	method := &signingMethodAKV{client: fake}

	if _, err := method.Sign("a.b", keyRef{name: "my-key"}); err == nil {
		t.Fatal("expected error to propagate from client.Sign, got nil")
	}
}

func TestSigningMethodAlg(t *testing.T) {
	method := &signingMethodAKV{}
	if got := method.Alg(); got != "RS256" {
		t.Errorf("Alg() = %q, want RS256", got)
	}
}

func TestSigningMethodVerifyNotImplemented(t *testing.T) {
	method := &signingMethodAKV{}
	if err := method.Verify("", "", nil); err == nil {
		t.Fatal("expected Verify to return not-implemented error, got nil")
	}
}

func TestAkvSignerSign(t *testing.T) {
	fake := &fakeKV{result: []byte("sig")}
	signer := &akvSigner{client: fake, key: keyRef{name: "my-key", version: "v2"}}

	token, err := signer.Sign(jwt.RegisteredClaims{Subject: "foo", Issuer: "bar"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// A JWT is three base64url segments joined by dots.
	if parts := strings.Split(token, "."); len(parts) != 3 {
		t.Errorf("token has %d segments, want 3: %q", len(parts), token)
	}

	// The signer forwards its configured key reference to Key Vault.
	if fake.gotName != "my-key" || fake.gotVersion != "v2" {
		t.Errorf("forwarded name/version = %q/%q, want my-key/v2", fake.gotName, fake.gotVersion)
	}
}
