terraform {
  backend "gcs" {
    bucket = "octo-sts-staging-tfstate-332kcg"
    prefix = "/octo-sts"
  }
  required_providers {
    ko     = { source = "ko-build/ko" }
    cosign = { source = "chainguard-dev/cosign" }
    # The load balancer explicitly retains EXTERNAL with google v8.
    # Keep the next major provider upgrade deliberate.
    google      = { source = "hashicorp/google", version = ">= 8.7.0, < 9.0.0" }
    google-beta = { source = "hashicorp/google-beta", version = ">= 8.7.0, < 9.0.0" }
  }
}
