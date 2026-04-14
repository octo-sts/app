// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package ghtransport

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	kms "cloud.google.com/go/kms/apiv1"
	"github.com/bradleyfalzon/ghinstallation/v2"
	metrics "github.com/chainguard-dev/terraform-infra-common/pkg/httpmetrics"
	"github.com/octo-sts/app/pkg/appconfig"
	envConfig "github.com/octo-sts/app/pkg/envconfig"
	"github.com/octo-sts/app/pkg/gcpkms"
	"github.com/octo-sts/app/pkg/ghinstall"
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

// baseTransport returns the HTTP transport used by every AppsTransport: the
// default transport, wrapped by the httpmetrics transport for rate-limit
// labelling, and optionally a quotaTap if a QuotaStore is provided.
func baseTransport(quota *ghinstall.QuotaStore) http.RoundTripper {
	base := metrics.WrapTransport(http.DefaultTransport)
	if quota != nil {
		base = &quotaTap{inner: base, store: quota}
	}
	return base
}

// NewFromAppConfig creates an AppsTransport from an appconfig.AppConfig entry.
// Exactly one of app.PrivateKey, app.PrivateKeyFile, or app.KMSKey must be set.
// If quota is non-nil, response headers are tapped into the QuotaStore for
// capacity-aware routing decisions.
func NewFromAppConfig(ctx context.Context, app appconfig.AppConfig, kmsClient *kms.KeyManagementClient, quota *ghinstall.QuotaStore) (*ghinstallation.AppsTransport, error) {
	base := baseTransport(quota)
	switch {
	case app.PrivateKey != "":
		return ghinstallation.NewAppsTransport(base, app.AppID, []byte(app.PrivateKey))
	case app.PrivateKeyFile != "":
		return ghinstallation.NewAppsTransportKeyFromFile(base, app.AppID, app.PrivateKeyFile)
	default:
		if app.KMSKey == "" {
			return nil, fmt.Errorf("no credential source for app %d", app.AppID)
		}
		signer, err := gcpkms.New(ctx, kmsClient, app.KMSKey)
		if err != nil {
			return nil, fmt.Errorf("error creating signer: %w", err)
		}
		return ghinstallation.NewAppsTransportWithOptions(base, app.AppID, ghinstallation.WithSigner(signer))
	}
}

// New creates an AppsTransport from legacy environment-variable config.
// It delegates to NewFromAppConfig after mapping the env fields.
func New(ctx context.Context, appID int64, kmsKey string, env *envConfig.EnvConfig, kmsClient *kms.KeyManagementClient, quota *ghinstall.QuotaStore) (*ghinstallation.AppsTransport, error) {
	return NewFromAppConfig(ctx, appconfig.AppConfig{
		AppID:          appID,
		PrivateKey:     env.AppSecretCertificateEnvVar,
		PrivateKeyFile: env.AppSecretCertificateFile,
		KMSKey:         kmsKey,
	}, kmsClient, quota)
}
