package octosts

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/v57/github"
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

	// TODO(mattmoor): Support a list of repositories within the org.
}

// Compile checks the trust policy for validity, and prepares internal state
// for validating tokens.
func (tp *TrustPolicy) Compile() error {
	// Check that we got exactly oneof Issuer[Pattern]
	switch {
	case tp.Issuer != "" && tp.IssuerPattern != "":
		return errors.New("trust policy: only one of issuer or issuer_pattern can be set, got both")
	case tp.Issuer == "" && tp.IssuerPattern == "":
		return errors.New("trust policy: one of issuer or issuer_pattern must be set, got neither")
	case tp.IssuerPattern != "":
		r, err := regexp.Compile(tp.IssuerPattern)
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
		r, err := regexp.Compile(tp.SubjectPattern)
		if err != nil {
			return err
		}
		tp.subjectPattern = r
	}

	// Compile the claim patterns.
	tp.claimPattern = make(map[string]*regexp.Regexp, len(tp.ClaimPattern))
	for k, v := range tp.ClaimPattern {
		r, err := regexp.Compile(v)
		if err != nil {
			return fmt.Errorf("error compiling claim_pattern[%q]: %w", k, err)
		}
		tp.claimPattern[k] = r
	}
	return nil
}

// CheckToken checks the token against the trust policy.
func (tp *TrustPolicy) CheckToken(token *oidc.IDToken) error {
	// Check the issuer.
	if tp.issuerPattern != nil {
		if !tp.issuerPattern.MatchString(token.Issuer) {
			return fmt.Errorf("trust policy: issuer %q did not match %q", token.Issuer, tp.IssuerPattern)
		}
	} else if tp.Issuer != "" {
		if token.Issuer != tp.Issuer {
			return fmt.Errorf("trust policy: issuer %q did not match %q", token.Issuer, tp.Issuer)
		}
	}

	// Check the subject.
	if tp.subjectPattern != nil {
		if !tp.subjectPattern.MatchString(token.Subject) {
			return fmt.Errorf("trust policy: subject %q did not match %q", token.Subject, tp.SubjectPattern)
		}
	} else if tp.Subject != "" {
		if token.Subject != tp.Subject {
			return fmt.Errorf("trust policy: subject %q did not match %q", token.Subject, tp.Subject)
		}
	}

	// Check the claims.
	for k, v := range tp.claimPattern {
		customClaims := make(map[string]interface{})
		if err := token.Claims(&customClaims); err != nil {
			return err
		}
		raw, ok := customClaims[k]
		if !ok {
			return fmt.Errorf("trust policy: expected claim %q not found in token", k)
		}
		val, ok := raw.(string)
		if !ok {
			return fmt.Errorf("trust policy: expected claim %q not a string", k)
		}
		if !v.MatchString(val) {
			return fmt.Errorf("trust policy: claim %q did not match %q", k, v)
		}
	}

	return nil
}
