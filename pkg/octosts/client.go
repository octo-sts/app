// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"net/http"

	"github.com/google/go-github/v88/github"
)

// newGitHubClient builds a GitHub client that talks through transport to
// baseURL, which is empty for github.com and set to an API endpoint for GitHub
// Enterprise Server.
//
// Every client-construction site in this package must go through this. An
// earlier revision of the org-allowlist read constructed its own client without
// the enterprise option, which sent the read to api.github.com on a GHES
// deployment; because an unreadable .github repository is treated as "this
// installation cannot see the file", that silently disabled issuer enforcement
// for the entire deployment.
//
// The returned error is plain: each caller wraps it in the form its own
// signature requires.
func newGitHubClient(transport http.RoundTripper, baseURL string) (*github.Client, error) {
	opts := []github.ClientOptionsFunc{github.WithTransport(transport)}
	if baseURL != "" {
		opts = append(opts, github.WithEnterpriseURLs(baseURL, baseURL))
	}
	return github.NewClient(opts...)
}
