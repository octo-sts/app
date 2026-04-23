terraform {
  backend "gcs" {
    bucket = "octo-sts-terraform-state"
    prefix = "/octo-sts"
  }
  required_providers {
    ko     = { source = "ko-build/ko" }
    cosign = { source = "chainguard-dev/cosign" }
  }
}
