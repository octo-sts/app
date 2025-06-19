# Octo-STS: Security Token Service for GitHub

## Overview

Octo-STS is a GitHub App that functions as a Security Token Service (STS) for the GitHub API. The primary goal of this application is to eliminate the need for GitHub Personal Access Tokens (PATs) by providing a secure federation mechanism for workloads to obtain short-lived GitHub tokens.

This documentation provides a technical overview of the Octo-STS repository, its components, and how they work together.

## Core Concept

Octo-STS allows workloads that can produce OIDC tokens (like GitHub Actions, Google Cloud, AWS, etc.) to federate with the STS API to obtain short-lived tokens for GitHub API interactions. These tokens are:

1. Limited in scope based on trust policies
2. Short-lived (unlike PATs which can have long expiration times)
3. Cannot be leaked (as they're generated on-demand and revoked after use)

## Repository Structure

The repository is organized into several key components:

- **Main App (`cmd/app`)**: The core STS service that handles token exchange
- **Webhook Handler (`cmd/webhook`)**: Validates trust policies in GitHub repositories
- **Probers (`cmd/prober` and `cmd/negative-prober`)**: Test the functionality of the STS service
- **Packages**:
  - `pkg/octosts`: Core STS functionality
  - `pkg/webhook`: Webhook handling and validation
  - `pkg/ghtransport`: GitHub API transport layer
  - `pkg/prober`: Probing functionality for service health checks
  - `pkg/envconfig`: Environment configuration handling
  - `pkg/gcpkms`: Google Cloud KMS integration
  - `pkg/maxsize`: Utility for limiting request sizes
  - And more...

## Key Components

### STS Service

Located primarily in `pkg/octosts/octosts.go`, the STS service:

1. Receives OIDC tokens from workloads
2. Validates these tokens against trust policies
3. Issues short-lived GitHub tokens with appropriate permissions

The STS service exposes a GRPC endpoint that implements the `SecurityTokenService` interface, allowing for token exchange.

### Trust Policies

Trust policies (defined in `pkg/octosts/trust_policy.go`) are the heart of Octo-STS's security model. They:

1. Define who can federate (via issuer and subject matching)
2. Specify what permissions to grant
3. Limit access to specific repositories

Trust policies are stored as YAML files in GitHub repositories at `.github/chainguard/{name}.sts.yaml`.

### Webhook Handler

Located in `pkg/webhook/webhook.go`, the webhook handler:

1. Listens for GitHub events (push, pull request, check suite)
2. Validates trust policies when they're created or modified
3. Creates GitHub check runs to report validation status

This ensures that trust policies are correctly formatted and valid before they're used.

### Probers

The repository includes probers (`cmd/prober` and `cmd/negative-prober`) that:

1. Test the STS service functionality
2. Verify that token exchanges work as expected
3. Ensure that permission boundaries are respected

These serve as both tests and health checks for the deployed service.

## Federation Flow

When a workload wants to access GitHub, the flow is:

1. Workload obtains an OIDC token (e.g., from GitHub Actions, GCP, AWS)
2. Workload sends this token to Octo-STS along with:
   - The repository scope (e.g., `owner/repo`)
   - The identity name (which trust policy to use)
3. Octo-STS validates the token against the trust policy
4. If valid, Octo-STS issues a short-lived GitHub token with the permissions specified in the trust policy
5. Workload uses this token to interact with GitHub API
6. Token is automatically revoked after use or expires

## Trust Policy Example

A simple trust policy looks like this:

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:octo-sts/example:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

This allows GitHub Actions workflows in the `octo-sts/example` repo running on the `main` branch to:
- Read repository contents
- Create and modify issues

## Deployment

The repository includes Infrastructure as Code (IaC) in the `iac/` directory, primarily using Terraform to deploy:

1. The STS service
2. Webhook handler
3. Probers for monitoring
4. Load balancers and other infrastructure

## Security Considerations

Octo-STS is designed with security in mind:

1. All trust policies are validated before use
2. Tokens are short-lived and limited in scope
3. All token exchanges are logged and traceable
4. Trust policies are stored in GitHub, enabling version control and review
5. The app requires minimal permissions by default and only grants what's specified in trust policies

## Monitoring and Metrics

The application includes:
- Metrics endpoints for Prometheus
- Tracing via OpenTelemetry
- Health checks via probers
- Event logging to Cloud Events

## Conclusion

Octo-STS provides a secure way to generate short-lived GitHub tokens for workloads without requiring long-lived Personal Access Tokens. By leveraging OIDC federation and GitHub's Apps model, it offers a more secure alternative to traditional authentication methods.