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
	"github.com/google/go-github/v62/github"
	"github.com/kelseyhightower/envconfig"
	"github.com/octo-sts/app/pkg/octosts"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

type envConfig struct {
	Domain string `envconfig:"STS_DOMAIN" required:"true"`
}

func Func(ctx context.Context) error {
	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		return err
	}

	xchg := sts.New(
		fmt.Sprintf("https://%s", env.Domain),
		"does-not-matter",
		sts.WithScope("octo-sts/prober"),
		sts.WithIdentity("prober"),
	)

	ts, err := idtoken.NewTokenSource(ctx, env.Domain /* aud */)
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
		if err := octosts.Revoke(ctx, res.AccessToken); err != nil {
			clog.WarnContextf(ctx, "failed to revoke token: %v", err)
		}
	}()

	ghc := github.NewClient(
		oauth2.NewClient(ctx,
			oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: res.AccessToken,
			}),
		),
	)

	// Check the `contents: read` permission by reading back the STS policy we
	// used to federate.
	file, _, _, err := ghc.Repositories.GetContents(ctx,
		"octo-sts", "prober",
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
		"octo-sts", "prober",
		&github.IssueListByRepoOptions{}); err != nil {
		return fmt.Errorf("failed to list issues: %w", err)
	}
	// Attempt to create an issue, which should fail because we don't have the `issues: write` permission.
	if _, _, err := ghc.Issues.Create(ctx,
		"octo-sts", "prober",
		&github.IssueRequest{
			Title: github.String("octo-sts prober was able to create an issue"),
			Body:  github.String("This should fail!"),
		}); err == nil {
		return fmt.Errorf("expected to fail creating an issue")
	}

	// TODO(mattmoor): List pull requests

	// Attempt to exchange with a non-existent identity, which should fail.
	if _, err := sts.New(
		fmt.Sprintf("https://%s", env.Domain),
		"does-not-matter",
		sts.WithScope("octo-sts/prober"),
		sts.WithIdentity("does-not-exist"),
	).Exchange(ctx, token.AccessToken); err == nil {
		return fmt.Errorf("expected to fail to exchange with a non-existent identity: %w", err)
	}

	return nil
}

func Negative(ctx context.Context) error {
	var env envConfig
	if err := envconfig.Process("", &env); err != nil {
		return err
	}

	xchg := sts.New(
		fmt.Sprintf("https://%s", env.Domain),
		"does-not-matter",
		sts.WithScope("octo-sts/prober"),
		sts.WithIdentity("prober"),
	)

	ts, err := idtoken.NewTokenSource(ctx, env.Domain /* aud */)
	if err != nil {
		return fmt.Errorf("failed to get new gcp token source %w", err)
	}

	token, err := ts.Token()
	if err != nil {
		return fmt.Errorf("failed to get new gcp token: %w", err)
	}

	_, err = xchg.Exchange(ctx, token.AccessToken)
	if err == nil {
		return fmt.Errorf("exchange should have failed")
	}

	return nil
}
