// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0
package tokensource

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"chainguard.dev/sdk/sts"
	"github.com/chainguard-dev/clog"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

type TokenSource struct {
	ctx                   context.Context
	url                   string
	org, repo, policyName string
	// Base token source (e.g. the cred we send to the STS service to exchange).
	base      oauth2.TokenSource
	sometimes rate.Sometimes

	// Output fields.
	tok *oauth2.Token
	err error
}

func NewTokenSource(ctx context.Context, stsURL string, org, repo, policyName string, ts oauth2.TokenSource) *TokenSource {
	return &TokenSource{
		ctx:        ctx,
		url:        stsURL,
		org:        org,
		repo:       repo,
		policyName: policyName,
		base:       ts,
		sometimes:  rate.Sometimes{Interval: 45 * time.Minute},
	}
}

// Token returns a token from the octosts service.
func (ts *TokenSource) Token() (*oauth2.Token, error) {
	// The token is refreshed periodically. Previous tokens are revoked before
	// returning the new refreshed one.
	ts.sometimes.Do(func() {
		ctx := ts.ctx
		clog.FromContext(ctx).Debugf("getting octosts token for %s/%s - %s", ts.org, ts.repo, ts.policyName)
		otok, err := ts.token()

		// Explicitly set the token to nil rather than a struct with an empty
		// token field
		if err != nil {
			ts.tok, ts.err = nil, err
			return
		}

		// If there's a previous token, revoke it.
		if ts.tok != nil {
			ts.Revoke()
		}
		ts.tok, ts.err = &oauth2.Token{
			TokenType:   "Bearer",
			AccessToken: otok,
		}, nil
	})
	return ts.tok, ts.err
}

func (ts *TokenSource) token() (string, error) {
	ctx := ts.ctx
	scope := ts.org
	if scope != "" {
		scope = fmt.Sprintf("%s/%s", ts.org, ts.repo)
	}

	xchg := sts.New(
		ts.url,
		ts.policyName,
		sts.WithScope(scope),
		sts.WithIdentity(ts.policyName),
	)

	token, err := ts.base.Token()
	if err != nil {
		return "", err
	}

	res, err := xchg.Exchange(ctx, token.AccessToken)
	if err != nil {
		return "", err
	}
	return res, nil
}

// Revoke revokes the current token.
func (ts *TokenSource) Revoke() error {
	ctx := ts.ctx
	req, err := http.NewRequest(http.MethodDelete, "https://api.github.com/installation/token", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req = req.WithContext(ctx)

	resp, err := oauth2.NewClient(ctx, ts).Do(req)
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
