# Octo-STS Token Exchange

This document explains the token exchange process in Octo-STS, which is the core functionality that allows workloads to convert OIDC tokens into GitHub access tokens.

## Exchange Process Overview

The token exchange process in Octo-STS follows these steps:

1. Client obtains an OIDC token from a supported identity provider (GitHub Actions, GCP, AWS, etc.)
2. Client sends this token to Octo-STS along with scope and identity parameters
3. Octo-STS validates the token against the specified trust policy
4. If valid, Octo-STS generates a GitHub token with the appropriate permissions
5. Octo-STS returns the token to the client

## API Details

### Exchange Endpoint

Octo-STS implements the Chainguard `SecurityTokenService` gRPC service:

```protobuf
service SecurityTokenService {
  rpc Exchange(ExchangeRequest) returns (RawToken);
  rpc ExchangeRefreshToken(ExchangeRefreshTokenRequest) returns (TokenPair);
}
```

For simple HTTP access, you can use:

```
curl -H "Authorization: Bearer ${TOKEN}" \
  "https://octo-sts.dev/sts/exchange?scope=${REPO}&identity=${NAME}"
```

Where:
- `${TOKEN}` is your OIDC token
- `${REPO}` is the repository scope (e.g., `octo-sts/example`)
- `${NAME}` is the identity name (matching the trust policy filename)

### Request Parameters

- **TOKEN**: An OIDC token from a supported identity provider
- **SCOPE**: The GitHub repository scope in the format `owner/repo`
  - For organization-level policies, just use the organization name
- **IDENTITY**: The identity name, which maps to the trust policy filename

### Response

The service returns a GitHub token with permissions specified in the trust policy.

## Client Implementation

### Using the Chainguard SDK

The simplest way to interact with Octo-STS is via the Chainguard SDK:

```go
import (
    "context"
    "fmt"
    
    "chainguard.dev/sdk/sts"
)

func getGitHubToken(ctx context.Context, oidcToken string) (string, error) {
    // Create an exchange client
    xchg := sts.New(
        "https://octo-sts.dev",
        "audience-value",
        sts.WithScope("owner/repo"),
        sts.WithIdentity("my-identity"),
    )
    
    // Exchange the OIDC token for a GitHub token
    res, err := xchg.Exchange(ctx, oidcToken)
    if err != nil {
        return "", fmt.Errorf("exchange failed: %w", err)
    }
    
    // Use the token and then revoke it when done
    defer func() {
        if err := octosts.Revoke(ctx, res.AccessToken); err != nil {
            // Handle error
        }
    }()
    
    return res.AccessToken, nil
}
```

### Manual HTTP Request

You can also make a direct HTTP request:

```bash
TOKEN="your-oidc-token"
REPO="owner/repo"
IDENTITY="my-identity"

curl -H "Authorization: Bearer ${TOKEN}" \
  "https://octo-sts.dev/sts/exchange?scope=${REPO}&identity=${IDENTITY}"
```

## Exchange with GitHub Actions

For GitHub Actions, you can use the workflow's OIDC token:

```yaml
jobs:
  exchange:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC token
    
    steps:
      - name: Get OIDC Token
        id: get-token
        run: |
          OIDC_TOKEN=$(curl -H "Authorization: Bearer $ACTIONS_ID_TOKEN" \
            "https://octo-sts.dev/sts/exchange?scope=owner/repo&identity=github-actions" \
            -s | jq -r .token)
          echo "::add-mask::$OIDC_TOKEN"
          echo "token=$OIDC_TOKEN" >> $GITHUB_OUTPUT
      
      - name: Use GitHub Token
        run: |
          curl -H "Authorization: Bearer ${{ steps.get-token.outputs.token }}" \
            "https://api.github.com/repos/owner/other-repo/issues"
```

## Exchange with Google Cloud

For Google Cloud workloads:

```go
import (
    "context"
    "fmt"
    
    "chainguard.dev/sdk/sts"
    "google.golang.org/api/idtoken"
)

func exchangeWithGCP(ctx context.Context) error {
    // Create an STS client
    xchg := sts.New(
        "https://octo-sts.dev",
        "does-not-matter",
        sts.WithScope("owner/repo"),
        sts.WithIdentity("gcp-identity"),
    )
    
    // Get a Google ID token
    ts, err := idtoken.NewTokenSource(ctx, "octo-sts.dev" /* audience */)
    if err != nil {
        return fmt.Errorf("failed to get token source: %w", err)
    }
    
    token, err := ts.Token()
    if err != nil {
        return fmt.Errorf("failed to get token: %w", err)
    }
    
    // Exchange for GitHub token
    res, err := xchg.Exchange(ctx, token.AccessToken)
    if err != nil {
        return fmt.Errorf("exchange failed: %w", err)
    }
    
    // Use the GitHub token...
    return nil
}
```

## Error Handling

Common errors during token exchange:

- **Unauthenticated**: Missing or invalid authorization header
- **InvalidArgument**: Malformed token or parameters
- **PermissionDenied**: Token doesn't match trust policy
- **NotFound**: Trust policy not found
- **Internal**: Server-side error during exchange

Each error includes a descriptive message to help diagnose the issue.

## Security Considerations

- Always revoke tokens after use with `octosts.Revoke()`
- Use the minimum required permissions in trust policies
- Limit the scope of trust policies to specific issuers and subjects
- Monitor token exchange events for suspicious activity

## Caching

Octo-STS includes caching to improve performance:

- Installation IDs are cached to reduce GitHub API calls
- Trust policies are cached with a 5-minute expiration

This improves response times while ensuring policies stay relatively up-to-date.

## Monitoring

Token exchanges emit events with metrics:

- Exchange timestamp
- Scope and identity
- Success/failure status
- Actor information (issuer, subject, claims)
- Token SHA256 (for audit purposes)

You can use these events for monitoring and alerting.