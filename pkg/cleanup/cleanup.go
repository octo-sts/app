// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package cleanup decides which trust policies in an organization are unused
// and can be proposed for removal, and which are only failing and should be
// reported instead. It does no I/O: callers list the policies, load exchange
// history, and act on the returned Plan.
package cleanup

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultWindow is how far back exchange history is consulted when Config
// leaves Window unset. It matches the exchange history retention octo-sts.dev
// keeps today.
const DefaultWindow = 90 * 24 * time.Hour

// ErrHistoryTooShort is returned when the exchange history does not reach back
// to the start of the window. A policy used before the oldest record would
// look unused, so no decision is safe.
var ErrHistoryTooShort = errors.New("cleanup: exchange history does not cover the window")

// Policy is one trust policy file in a repository of the organization.
type Policy struct {
	// Repo is the repository name, without the owner.
	Repo string
	// Identity is the policy name, the file name without ".sts.yaml".
	Identity string
	// LastChanged is when the policy file was last changed. The zero value
	// means unknown, and such a policy is never removed.
	LastChanged time.Time
	// DefaultBranch is the branch the policy was read from, or empty if
	// unknown.
	DefaultBranch string
}

// Usage summarizes the exchanges for one (scope, identity) pair.
type Usage struct {
	// Scope is the exchange scope as recorded: "org" or "org/repo".
	Scope string
	// Identity is the requested policy identity.
	Identity string
	// LastSucceeded is the most recent successful exchange, or zero if none.
	LastSucceeded time.Time
	// LastFailed is the most recent failed exchange, or zero if none.
	LastFailed time.Time
	// LastError is the error of the most recent failed exchange.
	LastError string
}

// Config holds the settings for one organization's decision.
type Config struct {
	// Org is the organization name.
	Org string
	// OrgPolicyRepo is the repository holding org-level policies.
	OrgPolicyRepo string
	// CleanupIdentity is the opt-in policy's identity. It is never removed.
	CleanupIdentity string
	// Window is how far back an exchange counts as use. Zero means
	// DefaultWindow.
	Window time.Duration
	// Now is the time the decision is made.
	Now time.Time
	// HistoryStart is the time of the oldest exchange record available.
	HistoryStart time.Time
}

// Failing is a policy that was kept because it was used, but whose exchanges
// since it last changed have all failed.
type Failing struct {
	Policy
	LastFailed time.Time
	LastError  string
}

// RepoPlan is the outcome for one repository.
type RepoPlan struct {
	Repo string
	// Remove lists policies with no exchanges in the window.
	Remove []Policy
	// Failing lists kept policies that only fail.
	Failing []Failing
}

// Plan is the outcome for an organization. Repos without anything to remove
// or report are left out, and the rest are sorted by name.
type Plan struct {
	// WindowStart is the oldest time an exchange still counts as use.
	WindowStart time.Time
	// Window is how far back from the decision exchanges counted.
	Window time.Duration
	Repos  []RepoPlan
}

// Decide sorts the organization's policies into those to remove and those to
// report as failing. Any exchange in the window counts as use, even a failed
// one, so a policy is only removed when nobody tried to use it.
func Decide(cfg Config, policies []Policy, usage []Usage) (Plan, error) {
	window := cfg.Window
	if window == 0 {
		window = DefaultWindow
	}
	if window < 0 {
		return Plan{}, fmt.Errorf("cleanup: window must be positive, got %s", window)
	}
	if cfg.Org == "" || cfg.OrgPolicyRepo == "" {
		return Plan{}, errors.New("cleanup: org and org policy repo must be set")
	}
	start := cfg.Now.Add(-window)
	if cfg.HistoryStart.IsZero() || cfg.HistoryStart.After(start) {
		return Plan{}, fmt.Errorf("%w: oldest record %s, window starts %s", ErrHistoryTooShort, cfg.HistoryStart.Format(time.RFC3339), start.Format(time.RFC3339))
	}

	byKey := make(map[usageKey]Usage, len(usage))
	for _, u := range usage {
		k := usageKey{scope: strings.ToLower(u.Scope), identity: u.Identity}
		byKey[k] = merge(byKey[k], u)
	}

	plans := map[string]*RepoPlan{}
	planFor := func(repo string) *RepoPlan {
		p, ok := plans[repo]
		if !ok {
			p = &RepoPlan{Repo: repo}
			plans[repo] = p
		}
		return p
	}

	for _, p := range policies {
		orgPolicy := strings.EqualFold(p.Repo, cfg.OrgPolicyRepo)
		if orgPolicy && p.Identity == cfg.CleanupIdentity {
			continue
		}

		// Exchanges name the policy by scope: "org/repo" for a repository
		// policy, and also "org" for one in the org policy repo.
		var u Usage
		for _, scope := range scopes(cfg.Org, p.Repo, orgPolicy) {
			u = merge(u, byKey[usageKey{scope: scope, identity: p.Identity}])
		}

		used := u.LastSucceeded.After(start) || u.LastFailed.After(start)
		if !used {
			// A policy with an unknown or recent change may be new and not
			// used yet, so it stays.
			if !p.LastChanged.IsZero() && p.LastChanged.Before(start) {
				planFor(p.Repo).Remove = append(planFor(p.Repo).Remove, p)
			}
			continue
		}

		// Judge failures only since the policy last changed, so a policy
		// that was fixed is not reported for its old errors.
		since := maxTime(start, p.LastChanged)
		if u.LastFailed.After(since) && !u.LastSucceeded.After(since) {
			planFor(p.Repo).Failing = append(planFor(p.Repo).Failing, Failing{
				Policy:     p,
				LastFailed: u.LastFailed,
				LastError:  u.LastError,
			})
		}
	}

	plan := Plan{WindowStart: start, Window: window}
	for _, p := range plans {
		slices.SortFunc(p.Remove, func(a, b Policy) int { return cmp.Compare(a.Identity, b.Identity) })
		slices.SortFunc(p.Failing, func(a, b Failing) int { return cmp.Compare(a.Identity, b.Identity) })
		plan.Repos = append(plan.Repos, *p)
	}
	slices.SortFunc(plan.Repos, func(a, b RepoPlan) int { return cmp.Compare(a.Repo, b.Repo) })
	return plan, nil
}

type usageKey struct {
	scope    string
	identity string
}

// scopes returns the lowercased exchange scopes that resolve to a policy in
// repo. Repository names are case-insensitive on GitHub; identities are file
// names and are matched exactly.
func scopes(org, repo string, orgPolicy bool) []string {
	s := []string{strings.ToLower(org + "/" + repo)}
	if orgPolicy {
		s = append(s, strings.ToLower(org))
	}
	return s
}

// merge combines two usage summaries, keeping the latest of each.
func merge(a, b Usage) Usage {
	a.LastSucceeded = maxTime(a.LastSucceeded, b.LastSucceeded)
	if b.LastFailed.After(a.LastFailed) {
		a.LastFailed = b.LastFailed
		a.LastError = b.LastError
	}
	return a
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
