terraform {
  backend "gcs" {
    bucket = "octo-sts-terraform-state"
    prefix = "/bootstrap"
  }
}
