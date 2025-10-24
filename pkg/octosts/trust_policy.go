// Copyright 2024 Chainguard, Inc.
// SPDX-License-Identifier: Apache-2.0

package octosts

import (
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v75/github"
	"github.com/octo-sts/app/pkg/oidcvalidate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type TrustPolicy struct {
	// Issuer to match against (exact match).
	Issuer string `json:"issuer,omitempty"`
	// Issuer regex pattern to match against.
	IssuerPattern string         `json:"issuer_pattern,omitempty"`
	issuerPattern *regexp.Regexp `json:"-"`

	// Subject to match against (exact match).
	Subject string `json:"subject,omitempty"`
	// Subject regex pattern to match against.
	SubjectPattern string         `json:"subject_pattern,omitempty"`
	subjectPattern *regexp.Regexp `json:"-"`

	// Audience to match against (exact match).
	Audience string `json:"audience,omitempty"`
	// Audience regex pattern to match against.
	AudiencePattern string         `json:"audience_pattern,omitempty"`
	audiencePattern *regexp.Regexp `json:"-"`

	// ClaimPattern is a map of claim names to regex patterns to match against.
	ClaimPattern map[string]string         `json:"claim_pattern,omitempty"`
	claimPattern map[string]*regexp.Regexp `json:"-"`

	// GitHub App installation permissions to request tokens with.
	// See https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app
	Permissions github.InstallationPermissions `json:"permissions,omitempty"`

	isCompiled bool `json:"-"`
}

type OrgTrustPolicy struct {
	TrustPolicy `json:",inline"`

	// Repositories is an optional scoping of repositories within the organization.
	// If not provided, all repositories available to the GitHub App within the organization
	// are included.
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

	// Check that we got oneof Audience[Pattern] or none.
	switch {
	case tp.Audience != "" && tp.AudiencePattern != "":
		return errors.New("trust policy: only one of audience or audience_pattern can be set, got both")
	case tp.AudiencePattern != "":
		r, err := regexp.Compile("^" + tp.AudiencePattern + "$")
		if err != nil {
			return err
		}
		tp.audiencePattern = r
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
func (tp *TrustPolicy) CheckToken(token *oidc.IDToken, domain string) (Actor, error) {
	act := Actor{
		Issuer:  token.Issuer,
		Subject: token.Subject,
		Claims:  make([]Claim, 0, len(tp.claimPattern)),
	}
	if !tp.isCompiled {
		return act, status.Errorf(codes.Internal, "trust policy: not compiled")
	}

	// Validate critical token fields
	if !oidcvalidate.IsValidIssuer(token.Issuer) {
		return act, status.Errorf(codes.InvalidArgument, "invalid issuer in token")
	}
	if !oidcvalidate.IsValidSubject(token.Subject) {
		return act, status.Errorf(codes.InvalidArgument, "invalid subject in token")
	}
	for _, aud := range token.Audience {
		if !oidcvalidate.IsValidAudience(aud) {
			return act, status.Errorf(codes.InvalidArgument, "invalid audience in token")
		}
	}

	// Check the issuer.
	switch {
	case tp.issuerPattern != nil:
		if !tp.issuerPattern.MatchString(token.Issuer) {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: issuer %q did not match pattern %q", token.Issuer, tp.IssuerPattern)
		}

	case tp.Issuer != "":
		if token.Issuer != tp.Issuer {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: issuer %q did not match %q", token.Issuer, tp.Issuer)
		}

	default:
		// Shouldn't be possible for compiled policies (defense in depth).
		return act, status.Errorf(codes.Internal, "trust policy: no issuer or issuer_pattern set")
	}

	// Check the subject.
	switch {
	case tp.subjectPattern != nil:
		if !tp.subjectPattern.MatchString(token.Subject) {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: subject %q did not match pattern %q", token.Subject, tp.SubjectPattern)
		}

	case tp.Subject != "":
		if token.Subject != tp.Subject {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: subject %q did not match %q", token.Subject, tp.Subject)
		}

	default:
		// Shouldn't be possible for compiled policies (defense in depth).
		return act, status.Errorf(codes.Internal, "trust policy: no subject or subject_pattern set")
	}

	// Check the audience.
	switch {
	case tp.audiencePattern != nil:
		// Check that the audience pattern matches at least one of the token's audiences.
		found := false
		for _, aud := range token.Audience {
			if tp.audiencePattern.MatchString(aud) {
				found = true
				break
			}
		}
		if !found {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: audience_pattern %q did not match any of %q", tp.AudiencePattern, token.Audience)
		}

	case tp.Audience != "":
		if !slices.Contains(token.Audience, tp.Audience) {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: audience %q did not match any of %q", tp.Audience, token.Audience)
		}

	default:
		// If `audience` or `audience_pattern` is not provided, we fall back to the domain.
		if !slices.Contains(token.Audience, domain) {
			return act, status.Errorf(codes.PermissionDenied, "trust policy: audience %q did not match any of %q", domain, token.Audience)
		}
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
				return act, status.Errorf(codes.PermissionDenied, "trust policy: expected claim %q not found in token", k)
			}

			// Convert bool claims into a string
			boolVal, ok := raw.(bool)
			if ok {
				raw = "false"
				if boolVal {
					raw = "true"
				}
			}
			val, ok := raw.(string)
			if !ok {
				return act, status.Errorf(codes.PermissionDenied, "trust policy: expected claim %q not a string", k)
			}
			act.Claims = append(act.Claims, Claim{
				Name:  k,
				Value: val,
			})
			if !v.MatchString(val) {
				return act, status.Errorf(codes.PermissionDenied, "trust policy: claim %q did not match %q", k, v)
			}
		}
	}

	return act, nil
}
