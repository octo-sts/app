# Installing and Configuring Octo-STS

This guide explains how to set up and configure Octo-STS for your organization.

## Prerequisites

Before installing Octo-STS, you'll need:

- A GitHub organization where you have admin privileges
- Infrastructure for hosting the service components (e.g., Google Cloud, AWS)
- Terraform installed for deploying the infrastructure

## Step 1: Create a GitHub App

1. Go to your GitHub organization settings
2. Navigate to "GitHub Apps" and create a new GitHub App
3. Configure the app with:
   - Name: "Octo-STS" (or your preferred name)
   - Homepage URL: Your service domain
   - Webhook URL: Your webhook domain + "/hook"
   - Webhook secret: Generate a secure random secret
   - Permissions: See the [README.md](../README.md) for the complete list of required permissions
4. Generate and download a private key for the app
5. Install the app in your organization

## Step 2: Prepare Environment Variables

Create a .env file with the following variables:

```
# GitHub App configuration
GITHUB_APP_ID=your-app-id
GITHUB_INSTALLATION_ID=your-installation-id
GITHUB_PRIVATE_KEY_PATH=path/to/private-key.pem
GITHUB_WEBHOOK_SECRET=your-webhook-secret

# Service configuration
STS_DOMAIN=your-sts-domain
PORT=8080
METRICS=true

# Optional for GCP integration
KMS_KEY=your-kms-key
```

## Step 3: Deploy the Infrastructure

1. Modify `iac/terraform.tfvars` with your configuration:

```hcl
project_id        = "your-gcp-project"
region            = "us-central1"
domain            = "your-sts-domain"
github_app_id     = "your-app-id"
github_webhook_secret = "your-webhook-secret"
```

2. Initialize and apply Terraform:

```bash
cd iac
terraform init
terraform apply
```

## Step 4: Deploy the Services

You can deploy the services using:

1. Google Cloud Run (recommended)
2. Kubernetes
3. Docker containers on other infrastructure

### For Google Cloud Run:

```bash
# Build and deploy the main STS service
gcloud run deploy octo-sts \
  --source cmd/app \
  --env-vars-file .env \
  --region us-central1 \
  --allow-unauthenticated

# Build and deploy the webhook service
gcloud run deploy octo-sts-webhook \
  --source cmd/webhook \
  --env-vars-file .env \
  --region us-central1 \
  --allow-unauthenticated

# Build and deploy the probers
gcloud run deploy octo-sts-prober \
  --source cmd/prober \
  --env-vars-file .env.prober \
  --region us-central1 \
  --no-allow-unauthenticated

gcloud run deploy octo-sts-negative-prober \
  --source cmd/negative-prober \
  --env-vars-file .env.prober \
  --region us-central1 \
  --no-allow-unauthenticated
```

## Step 5: Create Trust Policies

1. Create a `.github/chainguard` directory in your repositories
2. Add trust policies for your workloads, for example:

```yaml
# .github/chainguard/github-actions.sts.yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:your-org/your-repo:ref:refs/heads/main

permissions:
  contents: read
  issues: write
```

For organization-wide policies, create them in your `.github` repository:

```yaml
# .github/chainguard/cloud-build.sts.yaml
issuer: https://accounts.google.com
subject_pattern: '[0-9]+'
claim_pattern:
  email: '.*@your-domain\.com'

permissions:
  contents: read
  
repositories:
  - repo1
  - repo2
```

## Step 6: Configure Clients

For GitHub Actions:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: Get GitHub Token
        id: get-token
        run: |
          OIDC_TOKEN=$(curl -H "Authorization: Bearer $ACTIONS_ID_TOKEN" \
            "https://your-sts-domain/sts/exchange?scope=your-org/your-repo&identity=github-actions" \
            -s | jq -r .token)
          echo "::add-mask::$OIDC_TOKEN"
          echo "token=$OIDC_TOKEN" >> $GITHUB_OUTPUT
          
      - name: Use Token
        run: |
          curl -H "Authorization: token ${{ steps.get-token.outputs.token }}" \
            https://api.github.com/repos/your-org/your-repo/issues
```

For Google Cloud Build:

```yaml
steps:
- name: 'gcr.io/cloud-builders/curl'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
    TOKEN=$(curl -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=your-sts-domain" -s)
    
    GITHUB_TOKEN=$(curl -H "Authorization: Bearer $${TOKEN}" \
      "https://your-sts-domain/sts/exchange?scope=your-org/your-repo&identity=cloud-build" \
      -s | jq -r .token)
    
    # Use the token
    curl -H "Authorization: token $${GITHUB_TOKEN}" \
      https://api.github.com/repos/your-org/your-repo/issues
```

## Step 7: Set Up Monitoring

1. Configure monitoring for the probers
2. Set up alerts for prober failures
3. Configure logging to capture token exchange events

## Troubleshooting

### Common Issues

- **Webhook Validation Failures**: Check the trust policy format and GitHub check runs
- **Token Exchange Failures**: Verify the token issuer and subject match the trust policy
- **Permission Denied**: Ensure the trust policy includes the required permissions
- **Service Unavailable**: Check the service deployment and logs

### Logs

To view service logs in Google Cloud:

```bash
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=octo-sts"
```

### Testing

You can test the setup using `curl`:

```bash
# Get an identity token
TOKEN=$(gcloud auth print-identity-token --audiences=your-sts-domain)

# Exchange for GitHub token
curl -H "Authorization: Bearer ${TOKEN}" \
  "https://your-sts-domain/sts/exchange?scope=your-org/your-repo&identity=your-identity"
```

## Updating the GitHub App

If you need to update permissions for the GitHub App:

1. Go to your GitHub organization settings
2. Navigate to "GitHub Apps" and select your app
3. Update the permissions as needed
4. Users will be prompted to approve the new permissions

## Security Best Practices

1. Regularly review and audit trust policies
2. Use specific subject patterns rather than wildcards
3. Grant the minimum permissions needed
4. Monitor token exchange events for suspicious activity
5. Rotate webhook secrets periodically
6. Use organization-level trust policies for better control