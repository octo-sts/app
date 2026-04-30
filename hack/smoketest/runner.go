// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"

	"chainguard.dev/sdk/sts"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v84/github"
	"golang.org/x/oauth2"

	"github.com/octo-sts/app/pkg/octosts"
)

type TestResult struct {
	Name   string
	Passed bool
	Error  string
}

func RunTests(ctx context.Context, cfg *Config) []TestResult {
	results := make([]TestResult, 0, len(cfg.Tests))

	for _, tc := range cfg.Tests {
		result := runSingleTest(ctx, cfg.Domain, tc)
		if result.Passed {
			clog.FromContext(ctx).Infof("PASS: %s", result.Name)
		} else {
			clog.FromContext(ctx).Errorf("FAIL: %s: %s", result.Name, result.Error)
		}
		results = append(results, result)
	}

	return results
}

func runSingleTest(ctx context.Context, domain string, tc TestCase) TestResult {
	result := TestResult{Name: tc.Name}

	if tc.StickyRepeat > 0 {
		return runStickyTest(ctx, domain, tc)
	}

	token, err := MintGitHubActionsToken(domain)
	if err != nil {
		result.Error = fmt.Sprintf("minting OIDC token: %v", err)
		return result
	}

	xchg := sts.New(
		fmt.Sprintf("https://%s", domain),
		"does-not-matter",
		sts.WithScope(tc.Scope),
		sts.WithIdentity(tc.Identity),
	)

	res, err := xchg.Exchange(ctx, token)

	if tc.ExpectFailure {
		if err == nil {
			result.Error = "expected exchange to fail, but it succeeded"
			return result
		}
		if tc.ExpectedError != "" && !strings.Contains(err.Error(), tc.ExpectedError) {
			result.Error = fmt.Sprintf("expected error containing %q, got: %v", tc.ExpectedError, err)
			return result
		}
		result.Passed = true
		return result
	}

	if err != nil {
		result.Error = fmt.Sprintf("exchange failed: %v", err)
		return result
	}

	defer func() {
		if err := octosts.Revoke(ctx, res.AccessToken); err != nil {
			clog.FromContext(ctx).Warnf("failed to revoke token for %q: %v", tc.Name, err)
		}
	}()

	if tc.Verify != nil {
		if err := runVerifications(ctx, res.AccessToken, tc.Verify); err != nil {
			result.Error = fmt.Sprintf("verification failed: %v", err)
			return result
		}
	}

	result.Passed = true
	return result
}

// runStickyTest exchanges N times with the same identity and verifies all
// tokens come from the same GitHub App, proving sticky routing is working.
func runStickyTest(ctx context.Context, domain string, tc TestCase) TestResult {
	result := TestResult{Name: tc.Name}

	var appIDs []int64
	for i := range tc.StickyRepeat {
		token, err := MintGitHubActionsToken(domain)
		if err != nil {
			result.Error = fmt.Sprintf("exchange %d: minting OIDC token: %v", i+1, err)
			return result
		}

		xchg := sts.New(
			fmt.Sprintf("https://%s", domain),
			"does-not-matter",
			sts.WithScope(tc.Scope),
			sts.WithIdentity(tc.Identity),
		)

		res, err := xchg.Exchange(ctx, token)
		if err != nil {
			result.Error = fmt.Sprintf("exchange %d: %v", i+1, err)
			return result
		}

		ghc := github.NewClient(
			oauth2.NewClient(ctx,
				oauth2.StaticTokenSource(&oauth2.Token{
					AccessToken: res.AccessToken,
				}),
			),
		)
		app, _, err := ghc.Apps.Get(ctx, "")
		if err != nil {
			result.Error = fmt.Sprintf("exchange %d: GET /app failed: %v", i+1, err)
			return result
		}
		appIDs = append(appIDs, app.GetID())

		if err := octosts.Revoke(ctx, res.AccessToken); err != nil {
			clog.FromContext(ctx).Warnf("failed to revoke token for %q exchange %d: %v", tc.Name, i+1, err)
		}
	}

	for i, id := range appIDs {
		if id != appIDs[0] {
			result.Error = fmt.Sprintf("sticky routing broken: exchange 1 used app %d, exchange %d used app %d", appIDs[0], i+1, id)
			return result
		}
	}

	result.Passed = true
	return result
}

func runVerifications(ctx context.Context, accessToken string, v *Verify) error {
	ghc := github.NewClient(
		oauth2.NewClient(ctx,
			oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: accessToken,
			}),
		),
	)

	if v.ContentsRead != nil {
		cr := v.ContentsRead
		file, _, _, err := ghc.Repositories.GetContents(ctx,
			cr.Org, cr.Repo, cr.Path,
			&github.RepositoryContentGetOptions{},
		)
		if err != nil {
			return fmt.Errorf("contents_read(%s/%s/%s): %w", cr.Org, cr.Repo, cr.Path, err)
		}
		if _, err := file.GetContent(); err != nil {
			return fmt.Errorf("contents_read(%s/%s/%s) reading content: %w", cr.Org, cr.Repo, cr.Path, err)
		}
	}

	if v.IssuesRead != nil {
		ir := v.IssuesRead
		if _, _, err := ghc.Issues.ListByRepo(ctx,
			ir.Org, ir.Repo,
			&github.IssueListByRepoOptions{},
		); err != nil {
			return fmt.Errorf("issues_read(%s/%s): %w", ir.Org, ir.Repo, err)
		}
	}

	if v.PullRequestsRead != nil {
		pr := v.PullRequestsRead
		if _, _, err := ghc.PullRequests.List(ctx,
			pr.Org, pr.Repo,
			&github.PullRequestListOptions{},
		); err != nil {
			return fmt.Errorf("pull_requests_read(%s/%s): %w", pr.Org, pr.Repo, err)
		}
	}

	return nil
}
