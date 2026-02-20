// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import "time"

type Event struct {
	Actor          Actor           `json:"actor"`
	TrustPolicy    *OrgTrustPolicy `json:"trust_policy"`
	InstallationID int64           `json:"installation_id"`
	Scope          string          `json:"scope"`
	Identity       string          `json:"identity"`
	UserAgent      string          `json:"user_agent,omitempty"`
	TokenSHA256    string          `json:"token_sha256"`
	Error          string          `json:"error,omitempty"`
	Time           time.Time       `json:"time"`
}

type Actor struct {
	Issuer  string  `json:"iss"`
	Subject string  `json:"sub"`
	Claims  []Claim `json:"claims,omitempty"`
}

type Claim struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
