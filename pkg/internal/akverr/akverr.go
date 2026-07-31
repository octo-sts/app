// Copyright 2025 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package akverr provides helpers for handling Azure Key Vault SDK errors safely.
package akverr

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Sanitize replaces an Azure SDK error with one containing only its error code
// and HTTP status, stripping the message which embeds the request URL (the
// vault host and key name) and the full response body. Errors that are not
// Azure SDK errors are returned unchanged.
func Sanitize(err error) error {
	// AuthenticationFailedError renders the token endpoint, which embeds the
	// tenant ID, along with the response body. Its credential type and message
	// are unexported, so only the status code can be safely surfaced.
	var authErr *azidentity.AuthenticationFailedError
	if errors.As(err, &authErr) {
		if authErr.RawResponse != nil {
			return fmt.Errorf("azure authentication failed (HTTP %d)", authErr.RawResponse.StatusCode) //nolint:err113
		}
		return errors.New("azure authentication failed") //nolint:err113
	}

	// ResponseError renders the request method and URL, the status line and the
	// response body. The error code alone ("KeyNotFound", "Forbidden") carries
	// no resource identifiers.
	var respErr *azcore.ResponseError
	if errors.As(err, &respErr) {
		if respErr.ErrorCode != "" {
			return fmt.Errorf("%s", respErr.ErrorCode) //nolint:err113
		}
		return fmt.Errorf("HTTP %d %s", respErr.StatusCode, http.StatusText(respErr.StatusCode)) //nolint:err113
	}

	return err
}
