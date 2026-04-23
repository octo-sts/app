terraform {
  backend "gcs" {
    bucket = "octo-sts-staging-tfstate-332kcg"
    prefix = "/octo-sts"
  }
  required_providers {
    ko     = { source = "ko-build/ko" }
    cosign = { source = "chainguard-dev/cosign" }
  }
}
