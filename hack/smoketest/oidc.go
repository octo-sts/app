// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

type oidcTokenResponse struct {
	Value string `json:"value"`
}

func MintGitHubActionsToken(audience string) (string, error) {
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN must be set (are you running in GitHub Actions with id-token: write?)")
	}

	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parsing ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	// URL is from the trusted ACTIONS_ID_TOKEN_REQUEST_URL env var set by GitHub Actions.
	req, err := http.NewRequest(http.MethodGet, u.String(), nil) //nolint:gosec // URL from trusted GitHub Actions env var
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+requestToken)

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // URL from trusted GitHub Actions env var
	if err != nil {
		return "", fmt.Errorf("requesting OIDC token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OIDC token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding OIDC token response: %w", err)
	}

	if tokenResp.Value == "" {
		return "", fmt.Errorf("OIDC token response had empty value")
	}

	return tokenResp.Value, nil
}
