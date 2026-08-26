terraform {
  backend "gcs" {
    bucket = "octo-sts-terraform-state"
    prefix = "/octo-sts"
  }
  required_providers {
    ko     = { source = "ko-build/ko" }
    cosign = { source = "chainguard-dev/cosign" }
    # Cap below google v8: v8 changed the default load_balancing_scheme from
    # EXTERNAL to EXTERNAL_MANAGED, and GCP rejects that scheme change in place
    # on the existing serverless-gclb backend services. Remove this cap only
    # alongside a deliberate Classic -> Global external ALB migration.
    google      = { source = "hashicorp/google", version = ">= 4.79.0, < 8.0.0" }
    google-beta = { source = "hashicorp/google-beta", version = ">= 4.79.0, < 8.0.0" }
  }
}
