// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// Revoke revokes a security token.
// baseURL overrides the GitHub API base URL for GHES; when empty,
// the default https://api.github.com is used.
func Revoke(ctx context.Context, tok, baseURL string) error {
	u := "https://api.github.com/installation/token"
	if baseURL != "" {
		u = strings.TrimRight(baseURL, "/") + "/installation/token"
	}
	req, err := http.NewRequest(http.MethodDelete, u, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req = req.WithContext(ctx)
	req.Header.Add("Authorization", "Bearer "+tok)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// The token was revoked!
	return nil
}
