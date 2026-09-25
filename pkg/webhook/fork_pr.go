// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-github/v88/github"
)

// checkSuitePRHome finds the repository where a check suite's associated PR
// number is meaningful. GitHub may omit the base repository from sparse suite
// payloads, in which case the event repository remains the only known home.
func checkSuitePRHome(pr *github.PullRequest, eventOwner, eventRepo string) (owner, repo string, crossRepo bool, err error) {
	if pr == nil || pr.GetNumber() == 0 {
		return "", "", false, errors.New("check suite has an incomplete associated pull request")
	}
	base := pr.GetBase().GetRepo()
	if base == nil {
		return eventOwner, eventRepo, false, nil
	}

	name := base.GetFullName()
	switch {
	case name != "":
		owner, repo, err = splitRepoName(name)
		if err != nil {
			return "", "", false, err
		}
	case base.GetURL() != "":
		owner, repo, err = repoFromAPIURL(base.GetURL())
		if err != nil {
			return "", "", false, err
		}
	default:
		return eventOwner, eventRepo, false, nil
	}
	return owner, repo, !strings.EqualFold(owner, eventOwner) || !strings.EqualFold(repo, eventRepo), nil
}

func splitRepoName(fullName string) (owner, repo string, err error) {
	owner, repo, ok := strings.Cut(fullName, "/")
	if !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", fmt.Errorf("invalid repository name %q in check suite PR", fullName)
	}
	return owner, repo, nil
}

func repoFromAPIURL(raw string) (owner, repo string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("invalid repository API URL %q in check suite PR", raw)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "repos" && i+3 == len(parts) && parts[i+1] != "" && parts[i+2] != "" {
			return parts[i+1], parts[i+2], nil
		}
	}
	return "", "", fmt.Errorf("repository API URL %q has no owner/repo", raw)
}

func inaccessibleCrossRepoPR(err error) bool {
	var ghErr *github.ErrorResponse
	return errors.As(err, &ghErr) && ghErr.Response != nil &&
		(ghErr.Response.StatusCode == http.StatusForbidden || ghErr.Response.StatusCode == http.StatusNotFound)
}
