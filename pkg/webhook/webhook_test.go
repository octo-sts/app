// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package webhook

import (
	"testing"

	"github.com/octo-sts/app/pkg/octosts"
	"sigs.k8s.io/yaml"
)

func TestYAMLUnmarshalStrict(t *testing.T) {
	const orgPolicy = `
issuer: https://issuer.enforce.dev
subject: 9e8b549b441afc4f082e9dccb5d1eeda843af975
claim_pattern:
  email: .*

permissions:
  metadata: read
  administration: read

repositories: [] # Act over all of the repos in the org.
`
	const repoPolicy = `
issuer: https://issuer.enforce.dev
subject: 9e8b549b441afc4f082e9dccb5d1eeda843af975
claim_pattern:
  email: .*

permissions:
  metadata: read
  administration: read
`
	if err := yaml.UnmarshalStrict([]byte(orgPolicy), &octosts.OrgTrustPolicy{}); err != nil {
		t.Error(err)
	}

	tp := &octosts.TrustPolicy{}
	if err := yaml.UnmarshalStrict([]byte(orgPolicy), tp); err == nil {
		t.Errorf("Wanted error, got: %v", tp)
	}
	if err := yaml.UnmarshalStrict([]byte(repoPolicy), &octosts.TrustPolicy{}); err != nil {
		t.Error(err)
	}
}
