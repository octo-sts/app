# Octo-STS Documentation

This directory contains comprehensive technical documentation for Octo-STS, a Security Token Service for GitHub.

## Documentation Index

### Core Concepts

- [Overview](overview.md) - Introduction to Octo-STS and its architecture
- [Trust Policies](trust-policies.md) - Detailed guide to trust policy configuration
- [Token Exchange](token-exchange.md) - How token exchange works and API details

### Components

- [Webhook](webhook.md) - The webhook component for trust policy validation
- [Probers](probers.md) - Health checking and monitoring components

### Guides

- [Installation](installation.md) - How to install and configure Octo-STS

## Key Features

- **Federation**: Convert OIDC tokens from various providers into GitHub tokens
- **Security**: Eliminate long-lived PATs with short-lived, scoped tokens
- **Auditability**: Track token issuance and usage
- **Flexibility**: Support for different identity providers and permission models

## Architecture Overview

Octo-STS consists of several components:

1. **STS Service**: The core token exchange service
2. **Webhook Handler**: Validates trust policies in real-time
3. **Probers**: Test and monitor the service health
4. **Infrastructure**: Load balancers, Terraform configurations, etc.

## Quick References

### Trust Policy Example

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:octo-sts/example:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

### Exchange Command

```bash
curl -H "Authorization: Bearer ${OIDC_TOKEN}" \
  "https://octo-sts.dev/sts/exchange?scope=owner/repo&identity=my-identity"
```

## Further Reading

- Check the [original blog post](https://www.chainguard.dev/unchained/the-end-of-github-pats-you-cant-leak-what-you-dont-have) introducing Octo-STS
- Review the [repository README](../README.md) for additional context
- Explore the code in the repository to understand implementation details

## Contributing

If you find issues or have suggestions for improving this documentation, please open an issue or pull request in the repository.