# Octo-STS Trust Policies

Trust policies are the cornerstone of Octo-STS security. They define which identities can federate with GitHub and what permissions they receive.

## Trust Policy Location

Trust policies are stored in GitHub repositories at:

```
.github/chainguard/{name}.sts.yaml
```

Where `{name}` is the identity name used during token exchange.

## Trust Policy Types

### Repository Trust Policy

Repository trust policies apply to a specific repository and are stored within that repository.

Example:
```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:octo-sts/example:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

### Organization Trust Policy

Organization trust policies apply across repositories in an organization and are stored in the `.github` repository of the organization.

Example:
```yaml
issuer: https://accounts.google.com
subject_pattern: '[0-9]+'
claim_pattern:
  email: '.*@example\.com'

permissions:
  contents: read
  
repositories:
  - repo1
  - repo2
```

## Trust Policy Structure

### Required Fields

- **Issuer**: The OIDC token issuer URL (e.g., `https://token.actions.githubusercontent.com`)
  - Alternative: `issuer_pattern` for regex matching
- **Subject**: The expected subject claim value
  - Alternative: `subject_pattern` for regex matching

### Optional Fields

- **Audience**: The expected audience claim value
  - Alternative: `audience_pattern` for regex matching
  - Defaults to the STS domain if not specified
- **Claim Pattern**: Map of additional claims to validate via regex
- **Repositories**: (Organization policy only) List of repositories this policy applies to
- **Permissions**: GitHub permission settings to include in the token

## Pattern Matching

Trust policies support regex pattern matching for flexible identity federation:

- `issuer_pattern`: Regex pattern for the token issuer
- `subject_pattern`: Regex pattern for the token subject
- `audience_pattern`: Regex pattern for the token audience
- `claim_pattern`: Map of claim names to regex patterns

All patterns are anchored with `^` and `$` to ensure complete matching.

## GitHub Actions Example

For GitHub Actions, the issuer and subject have this format:

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:org/repo:ref:refs/heads/main
```

To allow any branch, you can use:

```yaml
issuer: https://token.actions.githubusercontent.com
subject_pattern: 'repo:org/repo:ref:refs/.*'
```

## Google Cloud Example

For Google Cloud identities, you might use:

```yaml
issuer: https://accounts.google.com
subject_pattern: '[0-9]+'
claim_pattern:
  email: '.*@example\.com'
```

This would allow any Google account with an email ending in `@example.com` to federate.

## Permissions

Permissions follow GitHub's permission model. Common permissions include:

```yaml
permissions:
  # Repository permissions
  actions: read        # GitHub Actions access
  contents: write      # Repository content access
  issues: write        # Issue management
  pull_requests: write # Pull request management
  
  # Organization permissions (for org-level tokens)
  members: read        # Access organization member list
  projects: write      # Project management
```

Each permission can be set to `read`, `write`, or omitted (no access).

## Validation

Trust policies are validated:

1. When they're created or modified (via webhook)
2. At exchange time (when a token is requested)

Validation ensures:
- The policy is well-formed YAML
- Required fields are present
- Pattern fields contain valid regex
- Permissions are valid GitHub permission scopes

## Security Considerations

- Store trust policies in a repository with limited write access
- Use specific subjects rather than broad patterns when possible
- Grant only the minimum permissions needed
- Use organization policies for broader control
- Review trust policies as part of your security audit process

## Troubleshooting

If token exchange fails, check:

1. The trust policy exists and is valid
2. The OIDC token issuer and subject match the policy
3. Any claim patterns are satisfied
4. The repository is included in organization policies
5. The GitHub App is installed in the organization