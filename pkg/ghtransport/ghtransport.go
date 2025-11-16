// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bradleyfalzon/ghinstallation/v2"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/ghinstall"
	"github.com/octo-sts/app/pkg/kms"
)

type ctxKey int

const installIDCtxKey ctxKey = 0

// EnrichContext adds GitHub App and installation ID values to the context so
// that the httpmetrics transport can label rate-limit metrics with the specific
// installation consuming quota, and so that the quota tap (if configured) can
// attribute X-RateLimit-Remaining headers to the right installation.
func EnrichContext(ctx context.Context, appID, installationID int64) context.Context {
	ctx = metrics.WithGitHubAppID(ctx, appID)
	ctx = metrics.WithGitHubInstallationID(ctx, installationID)
	ctx = context.WithValue(ctx, installIDCtxKey, installationID)
	return ctx
}

func installationIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(installIDCtxKey).(int64)
	return v
}

// quotaTap is a RoundTripper that updates a QuotaStore from each response's
// X-RateLimit-Remaining / X-RateLimit-Limit headers. Only installation-token
// requests are recorded — app-level JWT requests return the shared app rate
// limit (~5 000/hr) which would contaminate the per-installation store.
//
// ghinstallation uses "token <tok>" for installation tokens and "Bearer <jwt>"
// for app JWTs, so we gate on the "token " prefix.
type quotaTap struct {
	inner http.RoundTripper
	store *ghinstall.QuotaStore
}

func (q *quotaTap) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := q.inner.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	if installID := installationIDFromContext(req.Context()); installID != 0 &&
		strings.HasPrefix(req.Header.Get("Authorization"), "token ") {
		remaining, rerr := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
		limit, lerr := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit"))
		if rerr == nil && lerr == nil && limit > 0 {
			q.store.Update(installID, remaining, limit)
		}
	}
	return resp, err
}

// New creates a GitHub AppsTransport. If quota is non-nil, response headers
// are also tapped into the QuotaStore for capacity-aware routing decisions.
func New(ctx context.Context, appID int64, kmsKey string, env *envConfig.EnvConfig, kmsClient kms.KMS, quota *ghinstall.QuotaStore) (*ghinstallation.AppsTransport, error) {
	// Wrap the base HTTP transport so every GitHub response's X-RateLimit-*
	// headers populate the github_rate_limit_* metrics with the app_id and
	// installation_id labels set on the request context by EnrichContext.
	base := metrics.WrapTransport(http.DefaultTransport)
	if quota != nil {
		base = &quotaTap{inner: base, store: quota}
	}

	switch {
	case env.AppSecretCertificateEnvVar != "":
		atr, err := ghinstallation.NewAppsTransport(base, appID, []byte(env.AppSecretCertificateEnvVar))

		if err != nil {
			return nil, err
		}
		return atr, nil

	case env.AppSecretCertificateFile != "":
		atr, err := ghinstallation.NewAppsTransportKeyFromFile(base, appID, env.AppSecretCertificateFile)

		if err != nil {
			return nil, err
		}
		return atr, nil
	default:
		if kmsKey == "" {
			return nil, fmt.Errorf("no KMS key provided for app %d", appID)
		}

		signer, err := kmsClient.NewSigner()
		if err != nil {
			return nil, fmt.Errorf("error creating signer: %w", err)
		}

		atr, err := ghinstallation.NewAppsTransportWithOptions(base, appID, ghinstallation.WithSigner(signer))
		if err != nil {
			return nil, err
		}

		return atr, nil
	}
}
