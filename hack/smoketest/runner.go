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
		result := runSingleTest(ctx, cfg, tc)
		if result.Passed {
			clog.FromContext(ctx).Infof("PASS: %s", result.Name)
		} else {
			clog.FromContext(ctx).Errorf("FAIL: %s: %s", result.Name, result.Error)
		}
		results = append(results, result)
	}

	return results
}

func runSingleTest(ctx context.Context, cfg *Config, tc TestCase) TestResult {
	result := TestResult{Name: tc.Name}
	domain := cfg.Domain

	if tc.StickyRepeat > 0 {
		return runStickyTest(ctx, cfg.Domain, tc)
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

// runStickyTest proves that sticky routing works end-to-end by exploiting
// the GitHub check-run ownership constraint: only the app that created a
// check run can update it. The test exchanges a token, creates a check run,
// then exchanges again and updates the same check run. If the second token
// came from a different app, the update fails with 403.
func runStickyTest(ctx context.Context, domain string, tc TestCase) TestResult {
	result := TestResult{Name: tc.Name}

	owner, repo := parseScope(tc.Scope)
	if owner == "" || repo == "" {
		result.Error = fmt.Sprintf("invalid scope %q: expected owner/repo", tc.Scope)
		return result
	}

	// First exchange: create a check run.
	token1, err := exchangeToken(ctx, domain, tc.Scope, tc.Identity)
	if err != nil {
		result.Error = fmt.Sprintf("exchange 1: %v", err)
		return result
	}

	ghc1 := newGitHubClient(ctx, token1)

	// Get the latest commit SHA — CreateCheckRun requires a real SHA.
	branch, _, err := ghc1.Repositories.GetBranch(ctx, owner, repo, "main", 0)
	if err != nil {
		result.Error = fmt.Sprintf("getting HEAD SHA: %v", err)
		return result
	}
	headSHA := branch.GetCommit().GetSHA()

	checkRun, _, err := ghc1.Checks.CreateCheckRun(ctx, owner, repo, github.CreateCheckRunOptions{
		Name:       "octo-sts-sticky-routing-test",
		HeadSHA:    headSHA,
		Status:     github.Ptr("completed"),
		Conclusion: github.Ptr("success"),
	})
	if err != nil {
		result.Error = fmt.Sprintf("creating check run: %v", err)
		return result
	}
	clog.FromContext(ctx).Infof("created check run %d on %s/%s", checkRun.GetID(), owner, repo)

	// Clean up the check run and revoke token1 on exit.
	// Cleanup runs first (registered second, LIFO), then revoke.
	defer func() {
		if err := octosts.Revoke(ctx, token1); err != nil {
			clog.FromContext(ctx).Warnf("failed to revoke token 1 for %q: %v", tc.Name, err)
		}
	}()
	defer func() {
		_, _, _ = ghc1.Checks.UpdateCheckRun(ctx, owner, repo, checkRun.GetID(), github.UpdateCheckRunOptions{
			Name:       "octo-sts-sticky-routing-test",
			Status:     github.Ptr("completed"),
			Conclusion: github.Ptr("neutral"),
			Output: &github.CheckRunOutput{
				Title:   github.Ptr("Sticky routing smoke test"),
				Summary: github.Ptr("Automated test to verify sticky routing. Can be ignored."),
			},
		})
	}()

	for i := 1; i < tc.StickyRepeat; i++ {
		tokenN, err := exchangeToken(ctx, domain, tc.Scope, tc.Identity)
		if err != nil {
			result.Error = fmt.Sprintf("exchange %d: %v", i+1, err)
			return result
		}

		ghcN := newGitHubClient(ctx, tokenN)
		_, _, err = ghcN.Checks.UpdateCheckRun(ctx, owner, repo, checkRun.GetID(), github.UpdateCheckRunOptions{
			Name:       "octo-sts-sticky-routing-test",
			Status:     github.Ptr("completed"),
			Conclusion: github.Ptr("success"),
		})

		if rErr := octosts.Revoke(ctx, tokenN); rErr != nil {
			clog.FromContext(ctx).Warnf("failed to revoke token %d for %q: %v", i+1, tc.Name, rErr)
		}

		if err != nil {
			result.Error = fmt.Sprintf("exchange %d: updating check run %d failed (different app?): %v", i+1, checkRun.GetID(), err)
			return result
		}
		clog.FromContext(ctx).Infof("exchange %d: successfully updated check run %d (same app confirmed)", i+1, checkRun.GetID())
	}

	result.Passed = true
	return result
}

func exchangeToken(ctx context.Context, domain, scope, identity string) (string, error) {
	oidcToken, err := MintGitHubActionsToken(domain)
	if err != nil {
		return "", fmt.Errorf("minting OIDC token: %w", err)
	}
	xchg := sts.New(
		fmt.Sprintf("https://%s", domain),
		"does-not-matter",
		sts.WithScope(scope),
		sts.WithIdentity(identity),
	)
	res, err := xchg.Exchange(ctx, oidcToken)
	if err != nil {
		return "", err
	}
	return res.AccessToken, nil
}

func newGitHubClient(ctx context.Context, accessToken string) *github.Client {
	return github.NewClient(
		oauth2.NewClient(ctx,
			oauth2.StaticTokenSource(&oauth2.Token{
				AccessToken: accessToken,
			}),
		),
	)
}

func parseScope(scope string) (owner, repo string) {
	parts := strings.SplitN(scope, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
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
