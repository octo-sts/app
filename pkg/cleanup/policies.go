// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/google/go-github/v88/github"
)

const policySuffix = ".sts.yaml"

// ListPolicies returns the trust policies in every repository of org that the
// client's installation can read, with when each policy file last changed.
//
// Archived repositories are skipped: their policies still work, but a cleanup
// PR could never land there. Forks are included, since their policies are as
// live as any other.
func ListPolicies(ctx context.Context, client *github.Client, org, policyDir string) ([]Policy, error) {
	repos, err := listRepos(ctx, client, org)
	if err != nil {
		return nil, err
	}

	var policies []Policy
	for _, repo := range repos {
		_, entries, _, err := client.Repositories.GetContents(ctx, org, repo, policyDir, nil)
		if isNotFound(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cleanup: listing %s in %s/%s: %w", policyDir, org, repo, err)
		}
		for _, e := range entries {
			identity, ok := strings.CutSuffix(e.GetName(), policySuffix)
			if e.GetType() != "file" || !ok || identity == "" {
				continue
			}
			p := Policy{Repo: repo, Identity: identity}
			commits, _, err := client.Repositories.ListCommits(ctx, org, repo, &github.CommitsListOptions{
				Path:        path.Join(policyDir, e.GetName()),
				ListOptions: github.ListOptions{PerPage: 1},
			})
			if err != nil {
				return nil, fmt.Errorf("cleanup: last change of %s in %s/%s: %w", e.GetName(), org, repo, err)
			}
			if len(commits) > 0 {
				p.LastChanged = commits[0].GetCommit().GetCommitter().GetDate().Time
			}
			policies = append(policies, p)
		}
	}
	return policies, nil
}

// listRepos returns the names of the unarchived repositories in org that the
// installation can access.
func listRepos(ctx context.Context, client *github.Client, org string) ([]string, error) {
	var repos []string
	opts := &github.ListOptions{PerPage: 100}
	for {
		page, resp, err := client.Apps.ListRepos(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("cleanup: listing repositories: %w", err)
		}
		for _, r := range page.Repositories {
			if r.GetArchived() || !strings.EqualFold(r.GetOwner().GetLogin(), org) {
				continue
			}
			repos = append(repos, r.GetName())
		}
		if resp.NextPage == 0 {
			return repos, nil
		}
		opts.Page = resp.NextPage
	}
}

func isNotFound(err error) bool {
	var ghErr *github.ErrorResponse
	return errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound
}
