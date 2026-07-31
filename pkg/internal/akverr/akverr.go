// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package akverr provides helpers for handling Azure Key Vault SDK errors safely.
package akverr

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Sanitize replaces an Azure SDK error with one carrying only its error code,
// HTTP status, or transport failure class. The Azure SDK renders the request
// URL (vault host, key name and version) and the full response body into its
// error strings, so nothing derived from the original message is safe to
// return.
//
// Sanitize fails closed: an unrecognised error is replaced with a generic
// message rather than passed through, so a new SDK error type cannot silently
// start leaking. Callers that need the detail should log the original error
// through a protected logger before returning the sanitized one.
//
// Sanitize(nil) returns nil.
func Sanitize(err error) error {
	if err == nil {
		return nil
	}

	// AuthenticationFailedError renders the token endpoint, which embeds the
	// tenant ID, along with the response body. Its credential type and message
	// are unexported, so only the status code can be safely surfaced.
	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		if authErr.RawResponse != nil {
			return fmt.Errorf("azure authentication failed (HTTP %d)", authErr.RawResponse.StatusCode)
		}
		return errors.New("azure authentication failed")
	}

	// ResponseError renders the request method and URL, the status line and the
	// response body. The error code alone ("KeyNotFound", "Forbidden") carries
	// no resource identifiers.
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		if respErr.ErrorCode != "" {
			return fmt.Errorf("%s", respErr.ErrorCode) //nolint:err113
		}
		return fmt.Errorf("HTTP %d %s", respErr.StatusCode, http.StatusText(respErr.StatusCode))
	}

	// Transport failures never reached the service, so there is no Azure error
	// code to report. Both url.Error.URL and the error it wraps name the vault
	// host (a DNS failure renders as "lookup <vault>.vault.azure.net: ..."), so
	// classify the failure rather than echoing any part of it.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		var dnsErr *net.DNSError
		switch {
		case urlErr.Timeout():
			return errors.New("keyvault request timed out")
		case errors.As(err, &dnsErr):
			return errors.New("keyvault dns resolution failed")
		default:
			return errors.New("keyvault transport error")
		}
	}

	return errors.New("keyvault request failed")
}
