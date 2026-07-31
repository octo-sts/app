// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package akverr

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Identifiers that must never appear in a sanitized error.
const (
	vaultHost  = "acme-prod-vault.vault.azure.net"
	keyName    = "github-app-signing-key"
	tenantID   = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	secretBody = `{"error":{"code":"KeyNotFound","message":"Key not found: github-app-signing-key"}}`
)

// newResponse builds an *http.Response that mirrors what the Key Vault data
// plane returns, including the request URL that embeds the vault and key name.
func newResponse(t *testing.T, status int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://"+vaultHost+"/keys/"+keyName+"/sign", nil)
	if err != nil {
		t.Fatalf("could not build request: %v", err)
	}
	return &http.Response{
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		StatusCode: status,
		Request:    req,
		Body:       io.NopCloser(strings.NewReader(secretBody)),
	}
}

// assertNoLeak fails if any sensitive identifier survived sanitization.
func assertNoLeak(t *testing.T, got string) {
	t.Helper()
	for _, leak := range []string{vaultHost, keyName, tenantID, "Key not found"} {
		if strings.Contains(got, leak) {
			t.Errorf("sanitized error leaked %q: %s", leak, got)
		}
	}
}

func TestSanitizeResponseErrorKeepsOnlyErrorCode(t *testing.T) {
	raw := &azcore.ResponseError{
		ErrorCode:   "KeyNotFound",
		StatusCode:  http.StatusNotFound,
		RawResponse: newResponse(t, http.StatusNotFound),
	}

	// Guard the premise: the unsanitized error really does expose the vault.
	if !strings.Contains(raw.Error(), vaultHost) {
		t.Fatalf("premise failed: raw error does not contain the vault host: %s", raw.Error())
	}

	got := Sanitize(raw)
	if got.Error() != "KeyNotFound" {
		t.Errorf("Sanitize() = %q, want %q", got.Error(), "KeyNotFound")
	}
	assertNoLeak(t, got.Error())
}

func TestSanitizeResponseErrorWithoutCodeFallsBackToStatus(t *testing.T) {
	raw := &azcore.ResponseError{
		StatusCode:  http.StatusForbidden,
		RawResponse: newResponse(t, http.StatusForbidden),
	}

	got := Sanitize(raw)
	if want := "HTTP 403 Forbidden"; got.Error() != want {
		t.Errorf("Sanitize() = %q, want %q", got.Error(), want)
	}
	assertNoLeak(t, got.Error())
}

func TestSanitizeAuthenticationFailedError(t *testing.T) {
	// The token endpoint embeds the tenant ID.
	req, err := http.NewRequest(http.MethodPost, "https://login.microsoftonline.com/"+tenantID+"/oauth2/v2.0/token", nil)
	if err != nil {
		t.Fatalf("could not build request: %v", err)
	}
	raw := &azidentity.AuthenticationFailedError{
		RawResponse: &http.Response{
			Status:     "401 Unauthorized",
			StatusCode: http.StatusUnauthorized,
			Request:    req,
			Body:       io.NopCloser(strings.NewReader(`{"error":"invalid_client"}`)),
		},
	}

	got := Sanitize(raw)
	if want := "azure authentication failed (HTTP 401)"; got.Error() != want {
		t.Errorf("Sanitize() = %q, want %q", got.Error(), want)
	}
	assertNoLeak(t, got.Error())
}

func TestSanitizeAuthenticationFailedErrorWithoutResponse(t *testing.T) {
	got := Sanitize(&azidentity.AuthenticationFailedError{})
	if want := "azure authentication failed"; got.Error() != want {
		t.Errorf("Sanitize() = %q, want %q", got.Error(), want)
	}
}

func TestSanitizeUnwrapsWrappedAzureError(t *testing.T) {
	raw := &azcore.ResponseError{
		ErrorCode:   "Forbidden",
		StatusCode:  http.StatusForbidden,
		RawResponse: newResponse(t, http.StatusForbidden),
	}
	// Callers wrap before returning, so Sanitize must look through the chain.
	wrapped := fmt.Errorf("keyvault sign: %w", raw)

	got := Sanitize(wrapped)
	if got.Error() != "Forbidden" {
		t.Errorf("Sanitize() = %q, want %q", got.Error(), "Forbidden")
	}
	assertNoLeak(t, got.Error())
}

func TestSanitizeLeavesNonAzureErrorsUnchanged(t *testing.T) {
	// Local failures carry no Azure response data and stay useful verbatim.
	want := errors.New("invalid key reference type: string")

	got := Sanitize(want)
	if !errors.Is(got, want) {
		t.Errorf("Sanitize() = %v, want the original error unchanged", got)
	}
}

func TestSanitizeNil(t *testing.T) {
	if got := Sanitize(nil); got != nil {
		t.Errorf("Sanitize(nil) = %v, want nil", got)
	}
}

func TestSanitizedErrorIsStillWrappable(t *testing.T) {
	// Callers do fmt.Errorf("...: %w", Sanitize(err)), so the result must
	// behave like a normal error in a chain.
	sanitized := Sanitize(&azcore.ResponseError{
		ErrorCode:   "KeyNotFound",
		StatusCode:  http.StatusNotFound,
		RawResponse: newResponse(t, http.StatusNotFound),
	})
	wrapped := fmt.Errorf("keyvault sign: %w", sanitized)

	if !errors.Is(wrapped, sanitized) {
		t.Error("wrapped sanitized error does not unwrap to the sanitized error")
	}
	if !strings.HasPrefix(wrapped.Error(), "keyvault sign: KeyNotFound") {
		t.Errorf("wrapped error = %q, want it to start with %q", wrapped.Error(), "keyvault sign: KeyNotFound")
	}
	assertNoLeak(t, wrapped.Error())

	// The original ResponseError must not remain reachable through the chain,
	// or callers could recover the leaky message via errors.As.
	var respErr *azcore.ResponseError
	if errors.As(wrapped, &respErr) {
		t.Error("sanitized error still unwraps to the original *azcore.ResponseError")
	}
}
