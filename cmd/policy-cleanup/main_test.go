// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v88/github"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/cleanup"
	"github.com/octo-sts/app/pkg/cleanup/bigquery"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func testConfig() config {
	return config{
		Domain:        "octo-staging.dev",
		Apps:          []string{"octo-sts-staging", "octo-sts-staging-2"},
		Table:         "p.d.t",
		Identity:      "octo-sts-cleanup",
		OrgPolicyRepo: ".github",
		PolicyDir:     ".github/chainguard-staging",
		Window:        90 * 24 * time.Hour,
		DryRun:        true,
	}
}

// fake records what the job did against fake dependencies.
type fake struct {
	history   bigquery.History
	loadErr   error
	exchanges map[string]error // org -> exchange error; missing means success
	policies  map[string][]cleanup.Policy
	listErr   map[string]error

	exchanged []string
	revoked   []string
	listed    []string
	published []cleanup.Publisher
	plans     []cleanup.Plan
	since     time.Time
}

func (f *fake) deps() deps {
	return deps{
		now: func() time.Time { return now },
		load: func(_ context.Context, since, n time.Time) (bigquery.History, error) {
			if !n.Equal(now) {
				return bigquery.History{}, errors.New("load called with the wrong now")
			}
			f.since = since
			return f.history, f.loadErr
		},
		exchange: func(_ context.Context, org string) (string, func(), error) {
			f.exchanged = append(f.exchanged, org)
			if err := f.exchanges[org]; err != nil {
				return "", nil, err
			}
			return "token-" + org, func() { f.revoked = append(f.revoked, org) }, nil
		},
		list: func(_ context.Context, client *github.Client, org, policyDir string) ([]cleanup.Policy, error) {
			if client == nil || policyDir != ".github/chainguard-staging" {
				return nil, errors.New("list called without a client or with the wrong policy dir")
			}
			f.listed = append(f.listed, org)
			return f.policies[org], f.listErr[org]
		},
		publish: func(_ context.Context, p cleanup.Publisher, plan cleanup.Plan) error {
			f.published = append(f.published, p)
			f.plans = append(f.plans, plan)
			return nil
		},
	}
}

func old(d int) time.Time { return now.AddDate(0, 0, -d) }

// orgsFake has one opted-in org with an unused and a used policy, three that
// refuse the exchange in the ways an org that has not opted in does, and one
// whose exchange fails.
func orgsFake() *fake {
	usage := func(org string) []cleanup.Usage {
		return []cleanup.Usage{{Scope: org + "/svc", Identity: "used", LastSucceeded: old(1)}}
	}
	return &fake{
		history: bigquery.History{Start: old(95), Latest: now, Usage: map[string][]cleanup.Usage{
			"acme": usage("acme"), "missing": usage("missing"), "denied": usage("denied"),
			"pinned": usage("pinned"), "down": usage("down"),
		}},
		exchanges: map[string]error{
			"missing": status.Error(codes.NotFound, "unable to find trust policy"),
			"denied":  status.Error(codes.PermissionDenied, "token does not match trust policy"),
			"pinned":  status.Error(codes.FailedPrecondition, "trust policy app is not configured"),
			"down":    status.Error(codes.Unavailable, "unavailable"),
		},
		policies: map[string][]cleanup.Policy{"acme": {
			{Repo: "svc", Identity: "unused", LastChanged: old(200), DefaultBranch: "main"},
			{Repo: "svc", Identity: "used", LastChanged: old(200), DefaultBranch: "main"},
		}},
	}
}

func TestRunDryRun(t *testing.T) {
	f := orgsFake()
	err := run(t.Context(), testConfig(), f.deps())
	if err == nil || !strings.Contains(err.Error(), "down: exchanging for octo-sts-cleanup") {
		t.Fatalf("run() = %v, want the failing org's error", err)
	}
	if strings.Contains(err.Error(), "missing") || strings.Contains(err.Error(), "denied") || strings.Contains(err.Error(), "pinned") {
		t.Errorf("run() = %v, want orgs that did not opt in skipped quietly", err)
	}
	if want := []string{"acme", "denied", "down", "missing", "pinned"}; !reflect.DeepEqual(f.exchanged, want) {
		t.Errorf("exchanged = %v, want %v", f.exchanged, want)
	}
	if want := []string{"acme"}; !reflect.DeepEqual(f.listed, want) || !reflect.DeepEqual(f.revoked, want) {
		t.Errorf("listed %v and revoked %v, want %v", f.listed, f.revoked, want)
	}
	if len(f.published) != 0 {
		t.Errorf("published %d plans in a dry run", len(f.published))
	}
	if want := now.Add(-90 * 24 * time.Hour); !f.since.Equal(want) {
		t.Errorf("history loaded since %v, want %v", f.since, want)
	}
}

func TestRunPublishes(t *testing.T) {
	f := orgsFake()
	delete(f.exchanges, "down")
	delete(f.history.Usage, "down")
	cfg := testConfig()
	cfg.DryRun = false
	if err := run(t.Context(), cfg, f.deps()); err != nil {
		t.Fatalf("run() = %v", err)
	}
	if len(f.published) != 1 {
		t.Fatalf("published %d plans, want 1", len(f.published))
	}
	p := f.published[0]
	if p.Client == nil || !reflect.DeepEqual(p.Apps, []string{"octo-sts-staging", "octo-sts-staging-2"}) || p.Org != "acme" || p.PolicyDir != ".github/chainguard-staging" || p.Branch != "octo-sts/octo-sts-cleanup" {
		t.Errorf("publisher = %+v", p)
	}
	plan := f.plans[0]
	if plan.Window != cfg.Window || len(plan.Repos) != 1 || len(plan.Repos[0].Remove) != 1 || plan.Repos[0].Remove[0].Identity != "unused" {
		t.Errorf("plan = %+v, want only the unused policy removed", plan)
	}
	if !reflect.DeepEqual(f.revoked, []string{"acme"}) {
		t.Errorf("revoked = %v, want [acme]", f.revoked)
	}
}

func TestRunListFailure(t *testing.T) {
	// One org failing to list does not stop the next, and its token is
	// still revoked.
	f := orgsFake()
	f.exchanges = nil
	f.listErr = map[string]error{"acme": errors.New("graphql: boom")}
	err := run(t.Context(), testConfig(), f.deps())
	if err == nil || !strings.Contains(err.Error(), "acme: graphql: boom") {
		t.Fatalf("run() = %v, want acme's list error", err)
	}
	if len(f.listed) != 5 || len(f.revoked) != 5 {
		t.Errorf("listed %v, revoked %v, want all five orgs", f.listed, f.revoked)
	}
}

func TestRunRefusesShortHistory(t *testing.T) {
	for name, h := range map[string]bigquery.History{
		"no history":    {},
		"too short":     {Start: old(80), Latest: now, Usage: map[string][]cleanup.Usage{"acme": nil}},
		"stalled start": {Latest: old(2), Usage: map[string][]cleanup.Usage{"acme": nil}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fake{history: h}
			err := run(t.Context(), testConfig(), f.deps())
			if !errors.Is(err, cleanup.ErrHistoryTooShort) {
				t.Fatalf("run() = %v, want ErrHistoryTooShort", err)
			}
			if len(f.exchanged) != 0 {
				t.Errorf("exchanged for %v despite the short history", f.exchanged)
			}
		})
	}
}

func TestRunErrors(t *testing.T) {
	f := &fake{loadErr: errors.New("bigquery: boom")}
	if err := run(t.Context(), testConfig(), f.deps()); err == nil || !strings.Contains(err.Error(), "bigquery: boom") {
		t.Errorf("run() = %v, want the load error", err)
	}
	cfg := testConfig()
	cfg.Window = 0
	if err := run(t.Context(), cfg, (&fake{}).deps()); err == nil || !strings.Contains(err.Error(), "WINDOW") {
		t.Errorf("run() with no window = %v, want an error", err)
	}
}

func TestNotOptedIn(t *testing.T) {
	for code, want := range map[codes.Code]bool{
		codes.NotFound:           true,
		codes.PermissionDenied:   true,
		codes.FailedPrecondition: true,
		codes.InvalidArgument:    false, // our own token or issuer was rejected
		codes.Unauthenticated:    false,
		codes.Unavailable:        false,
		codes.Internal:           false,
	} {
		if got := notOptedIn(status.Error(code, "x")); got != want {
			t.Errorf("notOptedIn(%s) = %t, want %t", code, got, want)
		}
	}
	if notOptedIn(nil) || notOptedIn(errors.New("plain")) {
		t.Error("notOptedIn() of nil or a plain error = true, want false")
	}
}

func TestConfigDefaults(t *testing.T) {
	t.Setenv("STS_DOMAIN", "octo-sts.dev")
	t.Setenv("GITHUB_APP_SLUGS", "octo-sts,octo-sts-2")
	t.Setenv("EXCHANGE_TABLE", "p.d.t")
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		t.Fatal(err)
	}
	want := config{
		Domain: "octo-sts.dev", Apps: []string{"octo-sts", "octo-sts-2"}, Table: "p.d.t",
		Identity: "octo-sts-cleanup", OrgPolicyRepo: ".github", PolicyDir: ".github/chainguard",
		Window: cleanup.DefaultWindow, DryRun: true,
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v, want %+v", cfg, want)
	}
	for _, missing := range []string{"STS_DOMAIN", "GITHUB_APP_SLUGS", "EXCHANGE_TABLE"} {
		t.Run(missing, func(t *testing.T) {
			t.Setenv(missing, "") // restores it after the test
			os.Unsetenv(missing)
			if err := envconfig.Process("", &config{}); err == nil {
				t.Errorf("config without %s accepted", missing)
			}
		})
	}
}
