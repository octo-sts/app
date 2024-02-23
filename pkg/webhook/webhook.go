// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/octo-sts/pkg/octosts"
	"github.com/google/go-github/v58/github"
	"github.com/hashicorp/go-multierror"
	"gopkg.in/yaml.v2"
)

const (
	// See https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads#delivery-headers for list of available headers

	// HeaderDelivery is the GUID of the webhook event.
	HeaderDelivery = "X-GitHub-Delivery"
	// HeaderEvent is the event name of the webhook.
	HeaderEvent = "X-GitHub-Event"

	// zeroHash is a special SHA value indicating a non-existent commit,
	// i.e. when a branch is newly created or destroyed.
	zeroHash = "0000000000000000000000000000000000000000"
)

type Validator struct {
	Transport *ghinstallation.AppsTransport
	// Store multiple secrets to allow for rolling updates.
	// Only one needs to match for the event to be considered valid.
	WebhookSecret [][]byte
}

func (e *Validator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := clog.FromContext(r.Context()).With(
		HeaderDelivery, r.Header.Get(HeaderDelivery),
		HeaderEvent, r.Header.Get(HeaderEvent),
	)
	ctx := clog.WithLogger(r.Context(), log)

	payload, err := e.validatePayload(r)
	if err != nil {
		log.Errorf("error validating payload: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	eventType := github.WebHookType(r)
	event, err := github.ParseWebHook(eventType, payload)
	if err != nil {
		log.Errorf("error parsing webhook: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// For every event handler, return back an identifier that we can
	// return back to the webhook in case we need to debug. This could
	// be the resource that was created, an event ID, etc.
	var cr *github.CheckRun
	switch event := event.(type) {
	case *github.PullRequestEvent:
		cr, err = e.handlePullRequest(ctx, event)
	case *github.PushEvent:
		cr, err = e.handlePush(ctx, event)
	// TODO: CheckRun retry
	default:
		// Use accepted as "we got it but didn't do anything"
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err != nil {
		log.Errorf("error handling event %T: %v", event, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if cr != nil {
		log.Info("created CheckRun", "check_run", cr)
	}
	w.WriteHeader(http.StatusOK)
}

func (e *Validator) validatePayload(r *http.Request) ([]byte, error) {
	// Taken from github.ValidatePayload - we can't use this directly since the body is consumed.
	signature := r.Header.Get(github.SHA256SignatureHeader)
	if signature == "" {
		signature = r.Header.Get(github.SHA1SignatureHeader)
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	for _, s := range e.WebhookSecret {
		payload, err := github.ValidatePayloadFromBody(contentType, bytes.NewBuffer(body), signature, s)
		if err == nil {
			return payload, nil
		}
	}
	return nil, errors.New("no matching secrets")
}

func (e *Validator) handleSHA(ctx context.Context, client *github.Client, owner, repo, sha string, files []string) (*github.CheckRun, error) {
	log := clog.FromContext(ctx)

	// Commit doesn't exist - nothing to do.
	if sha == zeroHash {
		return nil, nil
	}

	err := e.validatePolicies(ctx, client, owner, repo, sha, files)
	// Whether or not the commit is verified, we still create a CheckRun.
	// The only difference is whether it shows up to the user as success or
	// failure.
	var conclusion, title string
	if err == nil {
		conclusion = "success"
		title = "Valid trust policy."
	} else {
		conclusion = "failure"
		title = "Invalid trust policy."
	}

	opts := github.CreateCheckRunOptions{
		Name:        "Octo STS",
		HeadSHA:     sha,
		ExternalID:  github.String(sha),
		Status:      github.String("completed"),
		Conclusion:  github.String(conclusion),
		StartedAt:   &github.Timestamp{Time: time.Now()},
		CompletedAt: &github.Timestamp{Time: time.Now()},
		Output: &github.CheckRunOutput{
			Title:   github.String(title),
			Summary: github.String(err.Error()),
		},
	}

	cr, _, err := client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		log.Errorf("error creating CheckRun: %v", err)
		return nil, err
	}
	return cr, nil
}

func (e *Validator) validatePolicies(ctx context.Context, client *github.Client, owner, repo string, sha string, files []string) error {
	var merr error
	for _, f := range files {
		log := clog.FromContext(ctx).With("path", f)

		resp, _, _, err := client.Repositories.GetContents(ctx, owner, repo, f, &github.RepositoryContentGetOptions{Ref: sha})
		if err != nil {
			log.Infof("failed to get content for: %v", err)
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			continue
		}

		raw, err := resp.GetContent()
		if err != nil {
			log.Infof("failed to read content: %v", err)
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
			continue
		}

		if err := yaml.UnmarshalStrict([]byte(raw), &octosts.TrustPolicy{}); err != nil {
			log.Infof("failed to parse trust policy: %v", err)
			merr = multierror.Append(merr, fmt.Errorf("%s: %w", f, err))
		}
	}

	return merr
}

func (e *Validator) handlePush(ctx context.Context, event *github.PushEvent) (*github.CheckRun, error) {
	log := clog.FromContext(ctx).With(
		"github/repo", event.GetRepo().GetFullName(),
		"github/installation", event.GetInstallation().GetID(),
		"github/action", event.GetAction(),
		"git/ref", event.GetRef(),
		"git/commit", event.GetAfter(),
		"github/user", event.GetSender().GetLogin(),
	)
	ctx = clog.WithLogger(ctx, log)

	owner := event.GetRepo().GetOwner().GetLogin()
	repo := event.GetRepo().GetName()
	sha := event.GetAfter()
	installationID := event.GetInstallation().GetID()

	client := github.NewClient(&http.Client{
		Transport: ghinstallation.NewFromAppsTransport(e.Transport, installationID),
	})

	// Check diff
	// TODO: Pagination?
	resp, _, err := client.Repositories.CompareCommits(ctx, owner, repo, event.GetBefore(), sha, &github.ListOptions{})
	if err != nil {
		return nil, err
	}
	var files []string
	for _, file := range resp.Files {
		if ok, err := filepath.Match(".github/chainguard/*.sts.yaml", file.GetFilename()); err == nil && ok {
			files = append(files, file.GetFilename())
		}
	}
	if len(files) == 0 {
		return nil, nil
	}

	return e.handleSHA(ctx, client, owner, repo, sha, files)
}

func (e *Validator) handlePullRequest(ctx context.Context, pr *github.PullRequestEvent) (*github.CheckRun, error) {
	log := clog.FromContext(ctx).With(
		"github/repo", pr.GetRepo().GetFullName(),
		"github/installation", pr.GetInstallation().GetID(),
		"github/action", pr.GetAction(),
		"github/pull_request", pr.GetNumber(),
		"git/commit", pr.GetPullRequest().GetHead().GetSHA(),
		"github/user", pr.GetSender().GetLogin(),
	)
	ctx = clog.WithLogger(ctx, log)

	owner := pr.GetRepo().GetOwner().GetLogin()
	repo := pr.GetRepo().GetName()
	sha := pr.GetPullRequest().GetHead().GetSHA()
	installationID := pr.GetInstallation().GetID()

	client := github.NewClient(&http.Client{
		Transport: ghinstallation.NewFromAppsTransport(e.Transport, installationID),
	})

	// Check diff
	var files []string
	resp, _, err := client.PullRequests.ListFiles(ctx, owner, repo, pr.GetNumber(), &github.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, file := range resp {
		if ok, err := filepath.Match(".github/chainguard/*.sts.yaml", file.GetFilename()); err == nil && ok {
			files = append(files, file.GetFilename())
		}
	}
	if len(files) == 0 {
		return nil, nil
	}

	return e.handleSHA(ctx, client, owner, repo, sha, files)
}
