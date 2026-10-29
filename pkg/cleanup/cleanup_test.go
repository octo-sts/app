// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package cleanup

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	now = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	// old is before the default window, recent is inside it.
	old    = now.Add(-200 * 24 * time.Hour)
	recent = now.Add(-10 * 24 * time.Hour)
)

func daysAgo(d int) time.Time { return now.Add(-time.Duration(d) * 24 * time.Hour) }

func config() Config {
	return Config{
		Org:             "acme",
		OrgPolicyRepo:   ".github",
		CleanupIdentity: "octo-sts-cleanup",
		Now:             now,
		HistoryStart:    old,
	}
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name        string
		policies    []Policy
		usage       []Usage
		wantRemove  map[string][]string // repo -> identities
		wantFailing map[string][]string
	}{{
		name:       "unused old policy is removed",
		policies:   []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		wantRemove: map[string][]string{"svc": {"deploy"}},
	}, {
		name:     "unused policy changed within the window is kept",
		policies: []Policy{{Repo: "svc", Identity: "deploy", LastChanged: recent}},
	}, {
		name:     "policy with unknown change date is kept",
		policies: []Policy{{Repo: "svc", Identity: "deploy"}},
	}, {
		name:     "successful use keeps the policy",
		policies: []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		usage:    []Usage{{Scope: "acme/svc", Identity: "deploy", LastSucceeded: recent}},
	}, {
		name:        "failed use keeps the policy and reports it",
		policies:    []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		usage:       []Usage{{Scope: "acme/svc", Identity: "deploy", LastFailed: recent, LastError: "denied"}},
		wantFailing: map[string][]string{"svc": {"deploy"}},
	}, {
		name:       "use before the window does not count",
		policies:   []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		usage:      []Usage{{Scope: "acme/svc", Identity: "deploy", LastSucceeded: daysAgo(91), LastFailed: daysAgo(95)}},
		wantRemove: map[string][]string{"svc": {"deploy"}},
	}, {
		name:     "fixed policy is not reported for old failures",
		policies: []Policy{{Repo: "svc", Identity: "deploy", LastChanged: daysAgo(20)}},
		usage:    []Usage{{Scope: "acme/svc", Identity: "deploy", LastFailed: daysAgo(30), LastError: "denied"}},
	}, {
		name:     "failure then success is not reported",
		policies: []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		usage:    []Usage{{Scope: "acme/svc", Identity: "deploy", LastFailed: daysAgo(30), LastSucceeded: daysAgo(5)}},
	}, {
		name:        "policy broken by an edit is reported",
		policies:    []Policy{{Repo: "svc", Identity: "deploy", LastChanged: daysAgo(20)}},
		usage:       []Usage{{Scope: "acme/svc", Identity: "deploy", LastSucceeded: daysAgo(30), LastFailed: daysAgo(5), LastError: "denied"}},
		wantFailing: map[string][]string{"svc": {"deploy"}},
	}, {
		name:     "org policy is used through the org scope",
		policies: []Policy{{Repo: ".github", Identity: "release", LastChanged: old}},
		usage:    []Usage{{Scope: "acme", Identity: "release", LastSucceeded: recent}},
	}, {
		name:     "org policy is used through its own repo scope",
		policies: []Policy{{Repo: ".github", Identity: "release", LastChanged: old}},
		usage:    []Usage{{Scope: "acme/.github", Identity: "release", LastSucceeded: recent}},
	}, {
		name:       "org scope does not count for a repository policy",
		policies:   []Policy{{Repo: "svc", Identity: "release", LastChanged: old}},
		usage:      []Usage{{Scope: "acme", Identity: "release", LastSucceeded: recent}},
		wantRemove: map[string][]string{"svc": {"release"}},
	}, {
		name:     "cleanup policy is never removed",
		policies: []Policy{{Repo: ".github", Identity: "octo-sts-cleanup", LastChanged: old}},
	}, {
		name:       "cleanup identity outside the org policy repo is not special",
		policies:   []Policy{{Repo: "svc", Identity: "octo-sts-cleanup", LastChanged: old}},
		wantRemove: map[string][]string{"svc": {"octo-sts-cleanup"}},
	}, {
		name:     "scopes match case-insensitively",
		policies: []Policy{{Repo: "Svc", Identity: "deploy", LastChanged: old}},
		usage:    []Usage{{Scope: "ACME/svc", Identity: "deploy", LastSucceeded: recent}},
	}, {
		name:       "identities match exactly",
		policies:   []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}},
		usage:      []Usage{{Scope: "acme/svc", Identity: "Deploy", LastSucceeded: recent}},
		wantRemove: map[string][]string{"svc": {"deploy"}},
	}, {
		name: "results are grouped by repo and sorted",
		policies: []Policy{
			{Repo: "web", Identity: "zeta", LastChanged: old},
			{Repo: "api", Identity: "beta", LastChanged: old},
			{Repo: "web", Identity: "alpha", LastChanged: old},
			{Repo: "quiet", Identity: "used", LastChanged: old},
		},
		usage:      []Usage{{Scope: "acme/quiet", Identity: "used", LastSucceeded: recent}},
		wantRemove: map[string][]string{"api": {"beta"}, "web": {"alpha", "zeta"}},
	}, {
		name: "failing policies are sorted",
		policies: []Policy{
			{Repo: "svc", Identity: "zeta", LastChanged: old},
			{Repo: "svc", Identity: "alpha", LastChanged: old},
		},
		usage: []Usage{
			{Scope: "acme/svc", Identity: "zeta", LastFailed: recent},
			{Scope: "acme/svc", Identity: "alpha", LastFailed: recent},
		},
		wantFailing: map[string][]string{"svc": {"alpha", "zeta"}},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := Decide(config(), tt.policies, tt.usage)
			if err != nil {
				t.Fatalf("Decide() = %v", err)
			}
			gotRemove, gotFailing := map[string][]string{}, map[string][]string{}
			var order []string
			for _, r := range plan.Repos {
				order = append(order, r.Repo)
				for _, p := range r.Remove {
					gotRemove[r.Repo] = append(gotRemove[r.Repo], p.Identity)
				}
				for _, f := range r.Failing {
					gotFailing[r.Repo] = append(gotFailing[r.Repo], f.Identity)
				}
				if len(r.Remove) == 0 && len(r.Failing) == 0 {
					t.Errorf("repo %q in plan with nothing to do", r.Repo)
				}
			}
			if tt.wantRemove == nil {
				tt.wantRemove = map[string][]string{}
			}
			if tt.wantFailing == nil {
				tt.wantFailing = map[string][]string{}
			}
			if !reflect.DeepEqual(gotRemove, tt.wantRemove) {
				t.Errorf("remove = %v, want %v", gotRemove, tt.wantRemove)
			}
			if !reflect.DeepEqual(gotFailing, tt.wantFailing) {
				t.Errorf("failing = %v, want %v", gotFailing, tt.wantFailing)
			}
			for i := 1; i < len(order); i++ {
				if order[i-1] >= order[i] {
					t.Errorf("repos not sorted: %v", order)
				}
			}
		})
	}
}

func TestDecideFailingDetails(t *testing.T) {
	// Two records for the same policy (scopes recorded in different case)
	// merge, and the report carries the latest failure.
	usage := []Usage{
		{Scope: "acme/svc", Identity: "deploy", LastFailed: daysAgo(30), LastError: "older"},
		{Scope: "Acme/Svc", Identity: "deploy", LastFailed: daysAgo(3), LastError: "newer"},
	}
	plan, err := Decide(config(), []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}}, usage)
	if err != nil {
		t.Fatalf("Decide() = %v", err)
	}
	if len(plan.Repos) != 1 || len(plan.Repos[0].Failing) != 1 {
		t.Fatalf("plan = %+v, want one failing policy", plan)
	}
	f := plan.Repos[0].Failing[0]
	if !f.LastFailed.Equal(daysAgo(3)) || f.LastError != "newer" {
		t.Errorf("failing = %v %q, want %v %q", f.LastFailed, f.LastError, daysAgo(3), "newer")
	}
	if want := now.Add(-DefaultWindow); !plan.WindowStart.Equal(want) {
		t.Errorf("WindowStart = %v, want %v", plan.WindowStart, want)
	}
	if plan.Window != DefaultWindow {
		t.Errorf("Window = %v, want %v", plan.Window, DefaultWindow)
	}
}

func TestDecideWindow(t *testing.T) {
	policies := []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}}
	usage := []Usage{{Scope: "acme/svc", Identity: "deploy", LastSucceeded: daysAgo(100)}}

	// A 90-day default treats a use 100 days ago as outside the window.
	plan, err := Decide(config(), policies, usage)
	if err != nil || len(plan.Repos) != 1 {
		t.Fatalf("Decide() = %+v, %v; want the policy removed", plan, err)
	}

	// A 120-day window still covers it.
	cfg := config()
	cfg.Window = 120 * 24 * time.Hour
	plan, err = Decide(cfg, policies, usage)
	if err != nil || len(plan.Repos) != 0 {
		t.Fatalf("Decide() = %+v, %v; want the policy kept", plan, err)
	}
}

func TestDecideErrors(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
		is      error
	}{{
		name:   "history starts after the window",
		mutate: func(c *Config) { c.HistoryStart = daysAgo(60) },
		is:     ErrHistoryTooShort,
	}, {
		name:   "no history",
		mutate: func(c *Config) { c.HistoryStart = time.Time{} },
		is:     ErrHistoryTooShort,
	}, {
		name:   "longer window than history",
		mutate: func(c *Config) { c.HistoryStart = daysAgo(90); c.Window = 180 * 24 * time.Hour },
		is:     ErrHistoryTooShort,
	}, {
		name:    "negative window",
		mutate:  func(c *Config) { c.Window = -time.Hour },
		wantErr: "window must be positive",
	}, {
		name:    "missing org",
		mutate:  func(c *Config) { c.Org = "" },
		wantErr: "org and org policy repo must be set",
	}, {
		name:    "missing org policy repo",
		mutate:  func(c *Config) { c.OrgPolicyRepo = "" },
		wantErr: "org and org policy repo must be set",
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config()
			tt.mutate(&cfg)
			_, err := Decide(cfg, []Policy{{Repo: "svc", Identity: "deploy", LastChanged: old}}, nil)
			switch {
			case err == nil:
				t.Fatal("Decide() = nil, want an error")
			case tt.is != nil && !errors.Is(err, tt.is):
				t.Fatalf("Decide() = %v, want %v", err, tt.is)
			case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
				t.Fatalf("Decide() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestDecideHistoryExactlyAtWindowStart(t *testing.T) {
	cfg := config()
	cfg.HistoryStart = now.Add(-DefaultWindow)
	if _, err := Decide(cfg, nil, nil); err != nil {
		t.Fatalf("Decide() = %v, want history starting at the window start to be enough", err)
	}
}
