// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package akv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Identifiers that must not leak out of a failed request.
const (
	vaultHost  = "acme-prod-vault.vault.azure.net"
	secretName = "github-webhook-signing-secret"
	secretID   = "https://" + vaultHost + "/secrets/" + secretName
)

// fakeCred satisfies azcore.TokenCredential without contacting Entra ID.
type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "fake-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// newTestClient points a real azsecrets client at a local test server, so the
// SDK's request/response handling is exercised without reaching Azure. The
// server uses TLS because Key Vault refuses to send credentials over plain HTTP.
func newTestClient(t *testing.T, status int, body any) *azsecrets.Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)

	client, err := azsecrets.NewClient(srv.URL, fakeCred{}, &azsecrets.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			// srv.Client() trusts the server's self-signed certificate.
			Transport: srv.Client(),
		},
		// The test server is not a real Key Vault domain.
		DisableChallengeResourceVerification: true,
	})
	require.NoError(t, err)
	return client
}

func TestGetSecretReturnsValue(t *testing.T) {
	client := newTestClient(t, http.StatusOK, map[string]string{
		"value": "s3cr3t-webhook-value",
		"id":    secretID + "/abc123",
	})

	got, err := GetSecret(context.Background(), client, secretID)
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t-webhook-value"), got)
}

func TestGetSecretWithExplicitVersion(t *testing.T) {
	client := newTestClient(t, http.StatusOK, map[string]string{
		"value": "pinned-version-value",
		"id":    secretID + "/abc123",
	})

	got, err := GetSecret(context.Background(), client, secretID+"/abc123")
	require.NoError(t, err)
	assert.Equal(t, []byte("pinned-version-value"), got)
}

func TestGetSecretRejectsMalformedIdentifier(t *testing.T) {
	client := newTestClient(t, http.StatusOK, map[string]string{"value": "unused"})

	// Each must produce an error, never a panic.
	for _, keyID := range []string{
		"",
		secretName,                           // bare name
		vaultHost + "/secrets/" + secretName, // no scheme
		"http://" + vaultHost + "/secrets/" + secretName, // not https
		"https://" + vaultHost,                           // no /secrets/ path
		"https://" + vaultHost + "/secrets",
		"https://" + vaultHost + "/keys/" + secretName, // wrong object type
		"arn:aws:secretsmanager:us-east-1:123:secret:foo",
	} {
		t.Run(keyID, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetSecret panicked on %q: %v", keyID, r)
				}
			}()
			got, err := GetSecret(context.Background(), client, keyID)
			assert.Error(t, err, "expected %q to be rejected", keyID)
			assert.Nil(t, got)
		})
	}
}

func TestGetSecretEmptyValue(t *testing.T) {
	client := newTestClient(t, http.StatusOK, map[string]string{
		"value": "",
		"id":    secretID,
	})

	got, err := GetSecret(context.Background(), client, secretID)
	assert.Nil(t, got)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret does not exist")
}

func TestGetSecretSanitizesAzureError(t *testing.T) {
	client := newTestClient(t, http.StatusNotFound, map[string]any{
		"error": map[string]string{
			"code":    "SecretNotFound",
			"message": "A secret with (name/id) " + secretName + " was not found in this key vault.",
		},
	})

	got, err := GetSecret(context.Background(), client, secretID)
	assert.Nil(t, got)
	require.Error(t, err)

	// The Azure error code survives, so failures stay diagnosable.
	assert.Contains(t, err.Error(), "SecretNotFound")

	// The vault host, secret name and response body must not reach the caller.
	for _, leak := range []string{vaultHost, secretName, "was not found in this key vault"} {
		assert.NotContains(t, err.Error(), leak,
			"sanitized error leaked %q", leak)
	}
}

func TestGetSecretSanitizesServerError(t *testing.T) {
	// A response with no Azure error code falls back to the HTTP status.
	client := newTestClient(t, http.StatusForbidden, map[string]string{})

	_, err := GetSecret(context.Background(), client, secretID)
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), vaultHost),
		"sanitized error leaked the vault host: %s", err)
}

func TestParseSecretID(t *testing.T) {
	t.Run("returns the vault URL", func(t *testing.T) {
		got, err := ParseSecretID(secretID)
		require.NoError(t, err)
		assert.Equal(t, "https://"+vaultHost, got)
	})

	t.Run("ignores the version when deriving the vault", func(t *testing.T) {
		got, err := ParseSecretID(secretID + "/abc123")
		require.NoError(t, err)
		assert.Equal(t, "https://"+vaultHost, got)
	})

	t.Run("accepts a Managed HSM host", func(t *testing.T) {
		// Managed HSM uses a different domain but the same identifier shape.
		got, err := ParseSecretID("https://acme-hsm.managedhsm.azure.net/secrets/" + secretName)
		require.NoError(t, err)
		assert.Equal(t, "https://acme-hsm.managedhsm.azure.net", got)
	})

	t.Run("rejects malformed identifiers", func(t *testing.T) {
		for _, id := range []string{
			"",
			secretName,
			"https://" + vaultHost,
			"https://" + vaultHost + "/secrets",
			"https://" + vaultHost + "/secrets/", // no name
			"https://" + vaultHost + "/keys/" + secretName,
			"http://" + vaultHost + "/secrets/" + secretName,
		} {
			t.Run(id, func(t *testing.T) {
				got, err := ParseSecretID(id)
				require.Error(t, err)
				assert.Empty(t, got)
				assert.Contains(t, err.Error(), "secret identifier")
			})
		}
	})
}
