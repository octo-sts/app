// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package akv

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/golang-jwt/jwt/v4"
)

// Provider must satisfy the kms.KMS contract (ghinstallation.Signer + io.Closer).
// These are asserted structurally rather than by importing pkg/kms, which would
// create an import cycle since pkg/kms depends on this package.
var (
	_ ghinstallation.Signer = (*Provider)(nil)
	_ io.Closer             = (*Provider)(nil)
)

// fakeKV is a stand-in for *azkeys.Client that records the request and returns
// a canned signature, so tests never contact Azure.
type fakeKV struct {
	gotName    string
	gotVersion string
	gotParams  azkeys.SignParameters
	calls      int
	result     []byte
	err        error
}

func (f *fakeKV) Sign(_ context.Context, name, version string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	f.calls++
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

// Key Vault key identifiers are self-describing: the vault, key name and
// (optional) version all come from the single KMS_KEYS entry, so these tests
// need no environment setup.
const (
	versionedKeyID   = "https://vault-a.vault.azure.net/keys/signing-key/abc123def"
	unversionedKeyID = "https://vault-b.vault.azure.net/keys/signing-key"
)

func TestSigningMethodSign(t *testing.T) {
	rawSig := []byte("fake-signature-bytes")
	fake := &fakeKV{result: rawSig}
	method := &signingMethodAKV{client: fake, ctx: context.Background()}

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

	// Key Vault signs a pre-computed digest, so the signing string must be
	// SHA-256 hashed locally before the call.
	wantDigest := sha256.Sum256([]byte(signingString))
	if string(fake.gotParams.Value) != string(wantDigest[:]) {
		t.Error("digest sent to Key Vault does not match sha256(signingString)")
	}
	if len(fake.gotParams.Value) != sha256.Size {
		t.Errorf("digest length = %d, want %d", len(fake.gotParams.Value), sha256.Size)
	}
}

func TestSigningMethodSignEmptyVersion(t *testing.T) {
	fake := &fakeKV{result: []byte("sig")}
	method := &signingMethodAKV{client: fake, ctx: context.Background()}

	if _, err := method.Sign("a.b", keyRef{name: "my-key"}); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	// Key Vault resolves an empty version to the current key version.
	if fake.gotVersion != "" {
		t.Errorf("version = %q, want empty (latest)", fake.gotVersion)
	}
}

func TestSigningMethodSignBadKeyType(t *testing.T) {
	fake := &fakeKV{}
	method := &signingMethodAKV{client: fake, ctx: context.Background()}

	if _, err := method.Sign("a.b", "not-a-keyRef"); err == nil {
		t.Fatal("expected error for invalid key reference type, got nil")
	}
	if fake.calls != 0 {
		t.Errorf("client.Sign called %d times, want 0 on bad key type", fake.calls)
	}
}

func TestSigningMethodSignPropagatesError(t *testing.T) {
	wantErr := errors.New("key vault boom")
	fake := &fakeKV{err: wantErr}
	method := &signingMethodAKV{client: fake, ctx: context.Background()}

	_, err := method.Sign("a.b", keyRef{name: "my-key"})
	if err == nil {
		t.Fatal("expected error to propagate from client.Sign, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
}

func TestSigningMethodSignPassesContext(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "carried")

	var gotCtx context.Context
	fake := &ctxCapturingKV{onSign: func(c context.Context) { gotCtx = c }}
	method := &signingMethodAKV{client: fake, ctx: ctx}

	if _, err := method.Sign("a.b", keyRef{name: "my-key"}); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if gotCtx == nil || gotCtx.Value(ctxKey{}) != "carried" {
		t.Error("stored context was not passed through to client.Sign")
	}
}

// ctxCapturingKV records the context handed to Sign.
type ctxCapturingKV struct {
	onSign func(context.Context)
}

func (c *ctxCapturingKV) Sign(ctx context.Context, _, _ string, _ azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	c.onSign(ctx)
	return azkeys.SignResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: []byte("sig")},
	}, nil
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

func TestProviderSign(t *testing.T) {
	fake := &fakeKV{result: []byte("sig")}
	p := &Provider{client: fake, key: keyRef{name: "my-key", version: "v2"}, ctx: context.Background()}

	token, err := p.Sign(jwt.RegisteredClaims{Subject: "foo", Issuer: "bar"})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	// A JWT is three base64url segments joined by dots.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3: %q", len(parts), token)
	}

	// The header must advertise the algorithm Key Vault actually used.
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("could not decode token header: %v", err)
	}
	if !strings.Contains(string(header), `"alg":"RS256"`) {
		t.Errorf("token header = %s, want alg RS256", header)
	}

	// The provider forwards its configured key reference to Key Vault.
	if fake.gotName != "my-key" || fake.gotVersion != "v2" {
		t.Errorf("forwarded name/version = %q/%q, want my-key/v2", fake.gotName, fake.gotVersion)
	}
}

func TestProviderSignPropagatesError(t *testing.T) {
	fake := &fakeKV{err: errors.New("key vault boom")}
	p := &Provider{client: fake, key: keyRef{name: "my-key"}, ctx: context.Background()}

	if _, err := p.Sign(jwt.RegisteredClaims{Subject: "foo"}); err == nil {
		t.Fatal("expected error to propagate from client.Sign, got nil")
	}
}

func TestProviderClose(t *testing.T) {
	p := &Provider{client: &fakeKV{}, ctx: context.Background()}
	if err := p.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
	// Close is a no-op, so it must stay safe to call more than once.
	if err := p.Close(); err != nil {
		t.Errorf("second Close() = %v, want nil", err)
	}
}

func TestNewProviderParsesVersionedKeyID(t *testing.T) {
	p, err := NewProvider(context.Background(), versionedKeyID)
	if err != nil {
		t.Fatalf("NewProvider returned error: %v", err)
	}
	if p.key.name != "signing-key" {
		t.Errorf("key name = %q, want signing-key", p.key.name)
	}
	if p.key.version != "abc123def" {
		t.Errorf("key version = %q, want abc123def", p.key.version)
	}
	if p.client == nil {
		t.Error("client is nil, want an initialised azkeys client")
	}
}

func TestNewProviderOmittedVersionMeansLatest(t *testing.T) {
	p, err := NewProvider(context.Background(), unversionedKeyID)
	if err != nil {
		t.Fatalf("NewProvider returned error: %v", err)
	}
	if p.key.name != "signing-key" {
		t.Errorf("key name = %q, want signing-key", p.key.name)
	}
	// A key identifier without a version resolves to the current version.
	if p.key.version != "" {
		t.Errorf("key version = %q, want empty (latest)", p.key.version)
	}
}

func TestNewProviderDistinguishesVaultsForSameKeyName(t *testing.T) {
	// The whole point of a self-describing identifier: the same key name in
	// two different vaults must resolve independently.
	a, err := NewProvider(context.Background(), "https://vault-a.vault.azure.net/keys/shared-name")
	if err != nil {
		t.Fatalf("NewProvider(vault-a) returned error: %v", err)
	}
	b, err := NewProvider(context.Background(), "https://vault-b.vault.azure.net/keys/shared-name")
	if err != nil {
		t.Fatalf("NewProvider(vault-b) returned error: %v", err)
	}
	if a.client == b.client {
		t.Error("both providers share one client, want a client per vault")
	}
}

func TestNewProviderRejectsMalformedKeyID(t *testing.T) {
	// Each of these must produce an error, never a panic.
	for _, keyID := range []string{
		"",
		"signing-key",                        // bare name, pre-refactor format
		"vault-a.vault.azure.net/keys/k",     // no scheme
		"arn:aws:kms:us-east-1:123:key/abcd", // wrong provider's identifier
		"https://vault-a.vault.azure.net",    // no /keys/<name> path
		"https://vault-a.vault.azure.net/keys",
	} {
		t.Run(keyID, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("NewProvider panicked on %q: %v", keyID, r)
				}
			}()
			if _, err := NewProvider(context.Background(), keyID); err == nil {
				t.Errorf("NewProvider(%q) = nil error, want an error", keyID)
			}
		})
	}
}

func TestNewProviderDetachesFromCallerContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p, err := NewProvider(ctx, versionedKeyID)
	if err != nil {
		t.Fatalf("NewProvider returned error: %v", err)
	}
	cancel()

	// The provider outlives the request that created it, so cancelling the
	// caller's context must not poison later signing calls.
	if err := p.ctx.Err(); err != nil {
		t.Errorf("provider context cancelled with caller: %v", err)
	}
}

func TestSignSanitizesAzureError(t *testing.T) {
	const (
		vaultHost = "acme-prod-vault.vault.azure.net"
		keyName   = "github-app-signing-key"
	)

	req, err := http.NewRequest(http.MethodPost, "https://"+vaultHost+"/keys/"+keyName+"/sign", nil)
	if err != nil {
		t.Fatalf("could not build request: %v", err)
	}
	azureErr := &azcore.ResponseError{
		ErrorCode:  "KeyNotFound",
		StatusCode: http.StatusNotFound,
		RawResponse: &http.Response{
			Status:     "404 Not Found",
			StatusCode: http.StatusNotFound,
			Request:    req,
			Body: io.NopCloser(strings.NewReader(
				`{"error":{"code":"KeyNotFound","message":"Key not found: ` + keyName + `"}}`)),
		},
	}

	p := &Provider{
		client: &fakeKV{err: azureErr},
		key:    keyRef{name: keyName},
		ctx:    context.Background(),
	}

	_, err = p.Sign(jwt.RegisteredClaims{Subject: "foo"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	// The Azure error code survives so failures stay diagnosable.
	if !strings.Contains(err.Error(), "KeyNotFound") {
		t.Errorf("error = %q, want it to contain the Azure error code", err)
	}

	// The vault host, key name and response body must not reach the caller.
	for _, leak := range []string{vaultHost, keyName, "Key not found"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("sanitized error leaked %q: %s", leak, err)
		}
	}
}
