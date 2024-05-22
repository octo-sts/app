// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v61/github"
)

type TrustPolicy struct {
	Issuer        string         `json:"issuer,omitempty"`
	IssuerPattern string         `json:"issuer_pattern,omitempty"`
	issuerPattern *regexp.Regexp `json:"-"`

	Subject        string         `json:"subject,omitempty"`
	SubjectPattern string         `json:"subject_pattern,omitempty"`
	subjectPattern *regexp.Regexp `json:"-"`

	ClaimPattern map[string]string         `json:"claim_pattern,omitempty"`
	claimPattern map[string]*regexp.Regexp `json:"-"`

	Permissions github.InstallationPermissions `json:"permissions,omitempty"`

	isCompiled bool `json:"-"`
}

type OrgTrustPolicy struct {
	TrustPolicy `json:",inline"`

	Repositories []string `json:"repositories,omitempty"`
}

// Compile checks the trust policy for validity, and prepares internal state
// for validating tokens.
func (tp *TrustPolicy) Compile() error {
	if tp.isCompiled {
		return errors.New("trust policy: already compiled")
	}

	// Check that we got exactly oneof Issuer[Pattern]
	switch {
	case tp.Issuer != "" && tp.IssuerPattern != "":
		return errors.New("trust policy: only one of issuer or issuer_pattern can be set, got both")
	case tp.Issuer == "" && tp.IssuerPattern == "":
		return errors.New("trust policy: one of issuer or issuer_pattern must be set, got neither")
	case tp.IssuerPattern != "":
		r, err := regexp.Compile("^" + tp.IssuerPattern + "$")
		if err != nil {
			return err
		}
		tp.issuerPattern = r
	}

	// Check that we got exactly oneof Subject[Pattern]
	switch {
	case tp.Subject != "" && tp.SubjectPattern != "":
		return errors.New("trust policy: only one of subject or subject_pattern can be set, got both")
	case tp.Subject == "" && tp.SubjectPattern == "":
		return errors.New("trust policy: one of subject or subject_pattern must be set, got neither")
	case tp.SubjectPattern != "":
		r, err := regexp.Compile("^" + tp.SubjectPattern + "$")
		if err != nil {
			return err
		}
		tp.subjectPattern = r
	}

	// Compile the claim patterns.
	tp.claimPattern = make(map[string]*regexp.Regexp, len(tp.ClaimPattern))
	for k, v := range tp.ClaimPattern {
		r, err := regexp.Compile("^" + v + "$")
		if err != nil {
			return fmt.Errorf("error compiling claim_pattern[%q]: %w", k, err)
		}
		tp.claimPattern[k] = r
	}

	// Mark the trust policy as compiled.
	tp.isCompiled = true
	return nil
}

// CheckToken checks the token against the trust policy.
func (tp *TrustPolicy) CheckToken(token *oidc.IDToken) (Actor, error) {
	act := Actor{
		Issuer:  token.Issuer,
		Subject: token.Subject,
		Claims:  make([]Claim, 0, len(tp.claimPattern)),
	}
	if !tp.isCompiled {
		return act, errors.New("trust policy: not compiled")
	}

	// Check the issuer.
	switch {
	case tp.issuerPattern != nil:
		if !tp.issuerPattern.MatchString(token.Issuer) {
			return act, fmt.Errorf("trust policy: issuer_pattern %q did not match %q", token.Issuer, tp.IssuerPattern)
		}

	case tp.Issuer != "":
		if token.Issuer != tp.Issuer {
			return act, fmt.Errorf("trust policy: issuer %q did not match %q", token.Issuer, tp.Issuer)
		}

	default:
		// Shouldn't be possible for compiled policies (defense in depth).
		return act, fmt.Errorf("trust policy: no issuer or issuer_pattern set")
	}

	// Check the subject.
	switch {
	case tp.subjectPattern != nil:
		if !tp.subjectPattern.MatchString(token.Subject) {
			return act, fmt.Errorf("trust policy: subject_pattern %q did not match %q", token.Subject, tp.SubjectPattern)
		}

	case tp.Subject != "":
		if token.Subject != tp.Subject {
			return act, fmt.Errorf("trust policy: subject %q did not match %q", token.Subject, tp.Subject)
		}

	default:
		// Shouldn't be possible for compiled policies (defense in depth).
		return act, fmt.Errorf("trust policy: no subject or subject_pattern set")
	}

	// Check the claims.
	if len(tp.claimPattern) != 0 {
		customClaims := make(map[string]interface{})
		if err := token.Claims(&customClaims); err != nil {
			return act, err
		}
		for k, v := range tp.claimPattern {
			raw, ok := customClaims[k]
			if !ok {
				return act, fmt.Errorf("trust policy: expected claim %q not found in token", k)
			}
			val, ok := raw.(string)
			if !ok {
				return act, fmt.Errorf("trust policy: expected claim %q not a string", k)
			}
			act.Claims = append(act.Claims, Claim{
				Name:  k,
				Value: val,
			})
			if !v.MatchString(val) {
				return act, fmt.Errorf("trust policy: claim %q did not match %q", k, v)
			}
		}
	}

	return act, nil
}
