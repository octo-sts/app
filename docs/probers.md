# Octo-STS Probers

Octo-STS includes prober components that continuously test and monitor the functionality of the STS service. This document explains how these probers work and their role in maintaining service reliability.

## Overview

Probers are standalone services that periodically test the Octo-STS functionality by:

1. Obtaining an OIDC token
2. Attempting to exchange it for a GitHub token
3. Testing the received token against expected permissions
4. Verifying that invalid exchanges fail as expected

There are two types of probers:
- **Positive Prober**: Tests successful token exchange and permissions
- **Negative Prober**: Tests that invalid exchanges fail properly

## Positive Prober

The positive prober (`cmd/prober/main.go`) tests that:

1. Valid OIDC tokens can be exchanged successfully
2. Returned GitHub tokens have the expected permissions
3. Permission boundaries are correctly enforced

### Test Flow

The positive prober follows this sequence:

1. Generate a Google Cloud identity token with Octo-STS domain as audience
2. Exchange this token for a GitHub token using identity "prober"
3. Test "contents: read" permission by reading the STS policy file
4. Test "issues: read" permission by listing issues in the prober repo
5. Test permission boundaries by attempting to create an issue (should fail)
6. Test non-existent identity exchange (should fail)
7. Revoke the token after use

### Configuration

The positive prober is configured via environment variables:

- **STS_DOMAIN**: The domain of the Octo-STS service

### Success Criteria

The prober succeeds when:
- Token exchange completes successfully
- Allowed operations succeed
- Disallowed operations fail
- Token revocation succeeds

## Negative Prober

The negative prober (`cmd/negative-prober/main.go`) tests that:

1. Invalid token exchanges fail properly
2. The system correctly rejects unauthorized access attempts

### Test Flow

The negative prober follows this sequence:

1. Generate a Google Cloud identity token
2. Attempt to exchange this token with a configuration expected to fail
3. Verify that the exchange properly fails

### Configuration

The negative prober is configured via environment variables:

- **STS_DOMAIN**: The domain of the Octo-STS service

### Success Criteria

The negative prober succeeds when the token exchange fails as expected. If the exchange unexpectedly succeeds, the prober reports an error.

## Deployment

Both probers are deployed as separate services in the infrastructure:

- They run on a schedule (typically every few minutes)
- They report status via metrics and logs
- They can trigger alerts when tests fail

## Implementation Details

The probers are implemented in:

- **Main Entry Points**: 
  - `cmd/prober/main.go`
  - `cmd/negative-prober/main.go`
- **Shared Logic**: `pkg/prober/prober.go`

They leverage:
- Google Cloud identity tokens for authentication
- Chainguard SDK for token exchange
- GitHub API for testing permissions

## Trust Policy Requirements

For the probers to work, the Octo-STS instance must have these trust policies:

1. A valid trust policy for the "prober" identity that grants:
   - `contents: read`
   - `issues: read`
   
2. No trust policy for the "does-not-exist" identity

## Monitoring

The probers integrate with monitoring systems to:

1. Expose metrics about success/failure rates
2. Generate logs for troubleshooting
3. Trigger alerts when failures occur

## Common Issues

Issues that probers might detect:

- **Service Downtime**: STS service is unavailable
- **Configuration Errors**: Trust policies are misconfigured
- **Permission Issues**: Token permissions don't match expectations
- **GitHub API Issues**: GitHub API rate limits or service issues
- **Identity Provider Issues**: Problems with the identity token source

## Best Practices

When working with probers:

1. Monitor prober success rates for early detection of issues
2. Review prober logs when investigating service problems
3. Update prober trust policies when making service changes
4. Use prober failures as an indicator of potential security issues

## Extending Probers

To extend the prober tests:

1. Add new test cases to the `Func` function in `pkg/prober/prober.go`
2. Update trust policies to include any new permissions needed
3. Update monitoring to track new test cases