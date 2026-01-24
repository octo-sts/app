# Octo-STS Webhook Handler

The webhook component of Octo-STS provides real-time validation of trust policies as they are created or modified in GitHub repositories. This document explains how the webhook works and its role in maintaining the security of the Octo-STS system.

## Overview

The webhook handler listens for specific GitHub events and validates trust policies to ensure they are properly formatted and follow security best practices. When a trust policy is created or modified, the webhook automatically validates it and creates a GitHub check run to report the results.

## Webhook Events

The webhook handler responds to the following GitHub events:

1. **Pull Request Events**: When a pull request that modifies a trust policy is created or updated
2. **Push Events**: When commits that modify trust policies are pushed directly to a branch
3. **Check Suite Events**: When a check suite is created for commits that modify trust policies
4. **Check Run Events**: Similar to check suite events but for individual check runs

## Validation Process

When a webhook event is received, the handler performs these steps:

1. **Authenticate**: Verify the GitHub webhook signature using the configured secret
2. **Extract Changes**: Identify which trust policies were created or modified
3. **Validate Policies**: Parse each policy and verify its format and content
4. **Create Check Run**: Report validation results as a GitHub check run

## Validation Criteria

Trust policies are validated against these criteria:

1. **YAML Syntax**: The file must be valid YAML
2. **Schema Compliance**: The structure must match the expected trust policy schema
3. **Required Fields**: All required fields (issuer, subject, etc.) must be present
4. **Pattern Validity**: Any regex patterns must be valid and compile successfully

## Check Run Results

After validation, the webhook creates a check run with:

- **Name**: "Trust Policy Validation"
- **Status**: "completed"
- **Conclusion**: "success" or "failure"
- **Details**: Error messages if validation failed

This check run appears in GitHub UI alongside other CI checks, making it clear when a trust policy is invalid.

## Configuration

The webhook handler can be configured with:

- **WebhookSecret**: Secret used to validate GitHub webhook signatures
- **OrganizationFilter**: Optional list of organizations to process (others are ignored)
- **Transport**: GitHub App transport for API access

## Deployment

The webhook handler is deployed as a separate service (`cmd/webhook/main.go`) that:

1. Listens for HTTP requests from GitHub
2. Validates webhook signatures
3. Processes events and validates policies
4. Creates GitHub check runs to report results

## Security Considerations

The webhook component enhances Octo-STS security by:

1. **Preventing Invalid Policies**: Invalid trust policies are clearly marked as failures
2. **Providing Feedback**: Developers receive immediate feedback on policy issues
3. **Creating Audit Trail**: Each policy change is validated and recorded
4. **Ensuring Consistency**: All policies follow the same validation standards

## Example Workflow

Here's how the webhook validation fits into typical development workflow:

1. Developer creates a new trust policy in a branch
2. Developer opens a pull request
3. Webhook automatically validates the policy
4. Validation results appear as a check run on the PR
5. If validation fails, developer fixes and pushes updates
6. When the policy passes validation, the PR can be merged
7. After merge, the policy is ready for use with token exchanges

## Implementation Details

The webhook handler is implemented in:

- **Main Entry**: `cmd/webhook/main.go`
- **Handler Logic**: `pkg/webhook/webhook.go`

It uses:
- GitHub's webhook payload validation
- GitHub's check run API
- The same policy validation logic used by the STS service

## Best Practices

To work effectively with the webhook validation:

1. Always test trust policy changes in a branch before merging
2. Check validation results in the PR before approving
3. Address any validation errors promptly
4. Consider using GitHub branch protection to require passing checks

## Troubleshooting

Common webhook issues:

- **Missing Check Runs**: Ensure the App has the `checks:write` permission
- **Validation Errors**: Review the check run details for specific error messages
- **Webhook Failures**: Check webhook delivery logs in GitHub
- **Missing Events**: Ensure webhook is configured for appropriate event types