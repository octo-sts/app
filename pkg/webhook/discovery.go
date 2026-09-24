// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/google/go-github/v88/github"
)

// isProvenWebhookRateLimit excludes ordinary permission 403s so discovery
// failures remain visible while genuine limits do not trigger redelivery.
func isProvenWebhookRateLimit(err error) bool {
	var rate *github.RateLimitError
	var abuse *github.AbuseRateLimitError
	if errors.As(err, &rate) || errors.As(err, &abuse) {
		return true
	}
	var response *github.ErrorResponse
	if !errors.As(err, &response) || response.Response == nil {
		return false
	}
	return response.Response.StatusCode == http.StatusTooManyRequests ||
		(response.Response.StatusCode == http.StatusForbidden &&
			(response.Response.Header.Get("X-RateLimit-Remaining") == "0" || response.Response.Header.Get("Retry-After") != ""))
}

const (
	prFilesPerPage = 100
	maxPRFiles     = 3000
	maxPRPages     = maxPRFiles / prFilesPerPage
	compareFileCap = 300
)

// policyFilesFromPR lists a complete, stable PR diff before selecting policies.
func (e *Validator) policyFilesFromPR(ctx context.Context, client *github.Client, owner, repo string, number int, expectedHead string) ([]string, error) {
	snapshot := func() (head, base string, count int, err error) {
		pr, resp, err := client.PullRequests.Get(ctx, owner, repo, number)
		if err != nil {
			return "", "", 0, err
		}
		if resp == nil || resp.Response == nil || pr == nil || pr.Head == nil || pr.Head.SHA == nil || pr.GetHead().GetSHA() == "" || pr.Base == nil || pr.Base.SHA == nil || pr.GetBase().GetSHA() == "" || pr.ChangedFiles == nil {
			return "", "", 0, fmt.Errorf("pull request %d has incomplete snapshot metadata", number)
		}
		return pr.GetHead().GetSHA(), pr.GetBase().GetSHA(), pr.GetChangedFiles(), nil
	}

	head, base, count, err := snapshot()
	if err != nil {
		return nil, err
	}
	if head != expectedHead {
		return nil, fmt.Errorf("pull request %d head %s differs from event head %s", number, head, expectedHead)
	}
	if count < 0 || count > maxPRFiles {
		return nil, fmt.Errorf("pull request %d has %d changed files; GitHub lists at most %d", number, count, maxPRFiles)
	}

	seen := make(map[string]struct{}, count)
	var files []*github.CommitFile
	page := 1
	for range maxPRPages {
		listed, resp, err := client.PullRequests.ListFiles(ctx, owner, repo, number, &github.ListOptions{Page: page, PerPage: prFilesPerPage})
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Response == nil || listed == nil {
			return nil, fmt.Errorf("pull request %d file page %d is incomplete", number, page)
		}
		for _, file := range listed {
			if file == nil || file.Filename == nil || file.GetFilename() == "" || file.Status == nil || file.GetStatus() == "" {
				return nil, fmt.Errorf("pull request %d file page %d has an incomplete entry", number, page)
			}
			if _, exists := seen[file.GetFilename()]; exists {
				return nil, fmt.Errorf("pull request %d repeats file %q", number, file.GetFilename())
			}
			seen[file.GetFilename()] = struct{}{}
			files = append(files, file)
		}
		if resp.NextPage == 0 {
			finalHead, finalBase, finalCount, err := snapshot()
			if err != nil {
				return nil, err
			}
			if head != finalHead || base != finalBase || count != finalCount || len(seen) != count {
				return nil, fmt.Errorf("pull request %d changed during file listing or returned an incomplete list", number)
			}
			return pathsToValidate(e.policyChangesFromCompare(ctx, repo, files)), nil
		}
		if resp.NextPage != page+1 {
			return nil, fmt.Errorf("pull request %d file pages jump from %d to %d", number, page, resp.NextPage)
		}
		page = resp.NextPage
	}
	return nil, fmt.Errorf("pull request %d exceeds %d file pages", number, maxPRPages)
}

// policyTreeSnapshot reads the full tree at a commit and refuses an incomplete
// response. It avoids the Compare API's 300-file limit.
func (e *Validator) policyTreeSnapshot(ctx context.Context, client *github.Client, owner, repo, ref string) (map[string]string, error) {
	commit, _, err := client.Git.GetCommit(ctx, owner, repo, ref)
	if err != nil {
		return nil, err
	}
	if commit == nil || commit.Tree == nil || commit.GetTree().GetSHA() == "" {
		return nil, fmt.Errorf("commit %s has no tree SHA", ref)
	}
	tree, _, err := client.Git.GetTree(ctx, owner, repo, commit.GetTree().GetSHA(), true)
	if err != nil {
		return nil, err
	}
	if tree == nil || tree.Truncated == nil || tree.Entries == nil || tree.GetTruncated() {
		return nil, fmt.Errorf("tree at %s is incomplete or truncated", ref)
	}
	out := make(map[string]string)
	for _, entry := range tree.Entries {
		if entry == nil || entry.GetSHA() == "" || entry.GetType() == "" || entry.GetPath() == "" {
			return nil, fmt.Errorf("tree at %s has an incomplete entry", ref)
		}
		switch entry.GetType() {
		case "blob":
			if isValidatedPath(repo, entry.GetPath(), e.policyRepo()) {
				out[entry.GetPath()] = entry.GetSHA()
			}
		case "tree", "commit":
		default:
			return nil, fmt.Errorf("tree at %s has unknown entry type %q", ref, entry.GetType())
		}
	}
	return out, nil
}

func (e *Validator) policyChangesFromTrees(ctx context.Context, client *github.Client, owner, repo, before, after string) ([]PolicyChange, error) {
	afterFiles, err := e.policyTreeSnapshot(ctx, client, owner, repo, after)
	if err != nil {
		return nil, err
	}
	beforeFiles := map[string]string{}
	if before != zeroHash {
		beforeFiles, err = e.policyTreeSnapshot(ctx, client, owner, repo, before)
		if err != nil {
			return nil, err
		}
	}
	var changes []PolicyChange
	for path, sha := range afterFiles {
		beforeSHA, existed := beforeFiles[path]
		switch {
		case !existed:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyCreated})
		case sha != beforeSHA:
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyUpdated})
		}
	}
	for path := range beforeFiles {
		if _, exists := afterFiles[path]; !exists {
			changes = append(changes, PolicyChange{Path: path, Policy: policyName(path), Action: PolicyDeleted})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	return changes, nil
}

func (e *Validator) completeCompareChanges(ctx context.Context, client *github.Client, owner, repo, before, after string, comparison *github.CommitsComparison) ([]PolicyChange, error) {
	if comparison == nil || comparison.Files == nil {
		return nil, errors.New("GitHub comparison omitted files")
	}
	for _, file := range comparison.Files {
		if file == nil || file.GetFilename() == "" || file.GetStatus() == "" {
			return nil, errors.New("GitHub comparison has an incomplete file entry")
		}
	}
	if len(comparison.Files) >= compareFileCap {
		return e.policyChangesFromTrees(ctx, client, owner, repo, before, after)
	}
	return e.policyChangesFromCompare(ctx, repo, comparison.Files), nil
}
