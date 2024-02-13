/*
Copyright 2024 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package prober

import (
	"context"
	"fmt"

	"chainguard.dev/sdk/sts"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/octo-sts/pkg/octosts"
	"github.com/google/go-github/v58/github"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func Func(ctx context.Context) error {
	xchg := sts.New(
		"https://octo-sts.dev",
		"does-not-matter",
		sts.WithScope("chainguard-dev/octo-sts-prober"),
		sts.WithIdentity("prober"),
	)

	ts, err := idtoken.NewTokenSource(ctx, "octo-sts.dev" /* aud */)
	if err != nil {
		return fmt.Errorf("failed to get new gcp token source %w", err)
	}

	token, err := ts.Token()
	if err != nil {
		return fmt.Errorf("failed to get new gcp token: %w", err)
	}

	res, err := xchg.Exchange(ctx, token.AccessToken)
	if err != nil {
		return fmt.Errorf("exchange failed: %w", err)
	}
	defer func() {
		if err := octosts.Revoke(ctx, res); err != nil {
			clog.WarnContextf(ctx, "failed to revoke token: %v", err)
		}
	}()

	ghc := github.NewClient(
		oauth2.NewClient(ctx,
			oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: res,
			}),
		),
	)

	// Check the `contents: read` permission by reading back the STS policy we
	// used to federate.
	file, _, _, err := ghc.Repositories.GetContents(ctx,
		"chainguard-dev", "octo-sts-prober",
		".github/chainguard/prober.sts.yaml",
		&github.RepositoryContentGetOptions{ /* defaults to the default branch */ },
	)
	if err != nil {
		return fmt.Errorf("failed to read back STS policy: %w", err)
	}
	if _, err := file.GetContent(); err != nil {
		return fmt.Errorf("failed to read file contents: %w", err)
	}

	// Check the `issues: read` permission by listing issues.
	if _, _, err := ghc.Issues.ListByRepo(ctx,
		"chainguard-dev", "octo-sts-prober",
		&github.IssueListByRepoOptions{}); err != nil {
		return fmt.Errorf("failed to list issues: %w", err)
	}
	// Attempt to create an issue, which should fail because we don't have the `issues: write` permission.
	if _, _, err := ghc.Issues.Create(ctx,
		"chainguard-dev", "octo-sts-prober",
		&github.IssueRequest{
			Title: github.String("octo-sts prober was able to create an issue"),
			Body:  github.String("This should fail!"),
		}); err == nil {
		return fmt.Errorf("expected to fail creating an issue")
	}

	// TODO(mattmoor): List pull requests

	// Attempt to exchange with a non-existent identity, which should fail.
	if _, err := sts.New(
		"https://octo-sts.dev",
		"does-not-matter",
		sts.WithScope("chainguard-dev/octo-sts-prober"),
		sts.WithIdentity("does-not-exist"),
	).Exchange(ctx, token.AccessToken); err != nil {
		return fmt.Errorf("expected to fail to exchange with a non-existent identity: %w", err)
	}

	return nil
}
