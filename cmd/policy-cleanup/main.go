// Copyright 2026 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

// Command policy-cleanup proposes removing trust policies nobody has used, in
// the organizations that opted in. It runs as a scheduled job.
//
// An organization opts in with a policy named CLEANUP_IDENTITY in its org
// policy repository that this job's identity can exchange for. Each run loads
// the deployment's exchange history once, then for every organization with
// exchanges in the window tries that exchange. Organizations where it is
// refused have not opted in and are skipped. For the rest it lists their
// policies, decides which are unused or only failing, and, unless DRY_RUN is
// set, opens or updates the cleanup pull requests and issues.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"chainguard.dev/sdk/sts"
	gbq "cloud.google.com/go/bigquery"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-github/v88/github"
	"github.com/kelseyhightower/envconfig"
	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/octo-sts/app/pkg/cleanup"
	"github.com/octo-sts/app/pkg/cleanup/bigquery"
	"github.com/octo-sts/app/pkg/octosts"
)

type config struct {
	// Domain is the octo-sts deployment to exchange with, such as
	// "octo-sts.dev".
	Domain string `envconfig:"STS_DOMAIN" required:"true"`
	// Apps are the slugs of every GitHub App that deployment uses, such as
	// "octo-sts,octo-sts-2", comma separated. Exchanges rotate across them,
	// so any of them may have opened last run's pull requests and issues.
	Apps []string `envconfig:"GITHUB_APP_SLUGS" required:"true"`
	// Table is the deployment's exchange table, "project.dataset.table". It
	// must record every exchange for the policies in PolicyDir, so
	// deployments sharing an organization need their own policy directories.
	Table string `envconfig:"EXCHANGE_TABLE" required:"true"`
	// Identity is the opt-in policy's name in the org policy repository.
	Identity      string        `envconfig:"CLEANUP_IDENTITY" default:"octo-sts-cleanup"`
	OrgPolicyRepo string        `envconfig:"ORG_POLICY_REPO" default:".github"`
	PolicyDir     string        `envconfig:"OCTOSTS_POLICY_DIR" default:".github/chainguard"`
	Window        time.Duration `envconfig:"WINDOW" default:"2160h"`
	// DryRun only logs the decisions. It is on unless turned off.
	DryRun bool `envconfig:"DRY_RUN" default:"true"`
}

// deps are the job's dependencies on the outside world.
type deps struct {
	now  func() time.Time
	load func(ctx context.Context, since, now time.Time) (bigquery.History, error)
	// exchange returns a token for org's opt-in policy and a func revoking it.
	exchange func(ctx context.Context, org string) (string, func(), error)
	list     func(ctx context.Context, client *github.Client, org, policyDir string) ([]cleanup.Policy, error)
	publish  func(ctx context.Context, p cleanup.Publisher, plan cleanup.Plan) error
}

func main() {
	// A failed run exits non-zero, which the job's alerting reports.
	if err := mainErr(); err != nil {
		log.Fatalf("policy cleanup failed: %v", err)
	}
}

func mainErr() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx = clog.WithLogger(ctx, clog.New(slog.Default().Handler()))

	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return fmt.Errorf("processing env vars: %w", err)
	}
	d, err := liveDeps(ctx, cfg)
	if err != nil {
		return err
	}
	return run(ctx, cfg, d)
}

func liveDeps(ctx context.Context, cfg config) (deps, error) {
	// Queries run in the table's project; bigquery.New validates the name.
	project, _, _ := strings.Cut(cfg.Table, ".")
	bq, err := gbq.NewClient(ctx, project)
	if err != nil {
		return deps{}, fmt.Errorf("creating BigQuery client: %w", err)
	}
	src, err := bigquery.New(bq, cfg.Table)
	if err != nil {
		return deps{}, err
	}
	ts, err := idtoken.NewTokenSource(ctx, cfg.Domain /* aud */)
	if err != nil {
		return deps{}, fmt.Errorf("creating ID token source: %w", err)
	}

	return deps{
		now:  time.Now,
		load: src.Load,
		exchange: func(ctx context.Context, org string) (string, func(), error) {
			id, err := ts.Token()
			if err != nil {
				return "", nil, fmt.Errorf("getting ID token: %w", err)
			}
			// Scope "org" names the org policy repository's policy.
			xchg := sts.New("https://"+cfg.Domain, "does-not-matter", sts.WithScope(org), sts.WithIdentity(cfg.Identity))
			res, err := xchg.Exchange(ctx, id.AccessToken)
			if err != nil {
				return "", nil, err
			}
			return res.AccessToken, func() {
				if err := octosts.Revoke(ctx, res.AccessToken, ""); err != nil {
					clog.WarnContextf(ctx, "revoking token for %s: %v", org, err)
				}
			}, nil
		},
		list: cleanup.ListPolicies,
		publish: func(ctx context.Context, p cleanup.Publisher, plan cleanup.Plan) error {
			return p.Publish(ctx, plan)
		},
	}, nil
}

// run cleans up every opted-in organization. A failure in one organization
// does not stop the others; all failures are returned together.
func run(ctx context.Context, cfg config, d deps) error {
	if cfg.Window <= 0 {
		return fmt.Errorf("WINDOW must be positive, got %s", cfg.Window)
	}
	now := d.now()
	since := now.Add(-cfg.Window)
	h, err := d.load(ctx, since, now)
	if err != nil {
		return err
	}
	// Decide checks this too, but without enough history no organization can
	// be decided, so stop before exchanging for any of them.
	if h.Start.IsZero() || h.Start.After(since) {
		return fmt.Errorf("%w: unbroken history starts %s, latest exchange %s, window starts %s",
			cleanup.ErrHistoryTooShort, h.Start.Format(time.RFC3339), h.Latest.Format(time.RFC3339), since.Format(time.RFC3339))
	}

	orgs := h.Orgs()
	slices.Sort(orgs)
	clog.InfoContextf(ctx, "checking %d organizations, history from %s, dry run %t", len(orgs), h.Start.Format(time.RFC3339), cfg.DryRun)

	var errs []error
	optedIn := 0
	for _, org := range orgs {
		ok, err := cleanOrg(ctx, cfg, d, h, org, now)
		if ok {
			optedIn++
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", org, err))
		}
	}
	clog.InfoContextf(ctx, "%d of %d organizations opted in, %d failed", optedIn, len(orgs), len(errs))
	return errors.Join(errs...)
}

// cleanOrg cleans up one organization, reporting whether it opted in.
func cleanOrg(ctx context.Context, cfg config, d deps, h bigquery.History, org string, now time.Time) (bool, error) {
	token, revoke, err := d.exchange(ctx, org)
	if notOptedIn(err) {
		clog.DebugContextf(ctx, "%s: skipped, not opted in: %v", org, err)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("exchanging for %s: %w", cfg.Identity, err)
	}
	defer revoke()

	client, err := github.NewClient(github.WithHTTPClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))))
	if err != nil {
		return true, err
	}
	policies, err := d.list(ctx, client, org, cfg.PolicyDir)
	if err != nil {
		return true, err
	}
	plan, err := cleanup.Decide(cleanup.Config{
		Org:             org,
		OrgPolicyRepo:   cfg.OrgPolicyRepo,
		CleanupIdentity: cfg.Identity,
		Window:          cfg.Window,
		Now:             now,
		HistoryStart:    h.Start,
	}, policies, h.For(org))
	if err != nil {
		return true, err
	}

	logPlan(ctx, org, len(policies), plan)
	if cfg.DryRun {
		return true, nil
	}
	return true, d.publish(ctx, cleanup.Publisher{
		Client:    client,
		Apps:      cfg.Apps,
		Org:       org,
		PolicyDir: cfg.PolicyDir,
		Branch:    "octo-sts/" + cfg.Identity,
	}, plan)
}

// notOptedIn reports whether an exchange was refused because the
// organization has no usable opt-in policy: it is missing or malformed
// (NotFound, which also covers an org without the App), rejects this job's
// token (PermissionDenied), or pins an App this deployment lacks
// (FailedPrecondition). Anything else, such as this job's own token being
// rejected or octo-sts being unavailable, is a failure.
func notOptedIn(err error) bool {
	switch status.Code(err) {
	case codes.NotFound, codes.PermissionDenied, codes.FailedPrecondition:
		return true
	default:
		return false
	}
}

func logPlan(ctx context.Context, org string, policies int, plan cleanup.Plan) {
	removes, failing := 0, 0
	for _, r := range plan.Repos {
		removes += len(r.Remove)
		failing += len(r.Failing)
		for _, p := range r.Remove {
			clog.InfoContextf(ctx, "%s/%s: unused policy %s, last changed %s", org, r.Repo, p.Identity, p.LastChanged.Format(time.DateOnly))
		}
		for _, f := range r.Failing {
			clog.InfoContextf(ctx, "%s/%s: failing policy %s, last failed %s", org, r.Repo, f.Identity, f.LastFailed.Format(time.DateOnly))
		}
	}
	clog.InfoContextf(ctx, "%s: %d policies, %d unused, %d only failing, in %d repositories", org, policies, removes, failing, len(plan.Repos))
}
