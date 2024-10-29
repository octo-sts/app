provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }

resource "google_project_service" "iamcredentials-api" {
  project                    = var.project_id
  service                    = "iamcredentials.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

data "google_monitoring_notification_channel" "notify-chainguard-slack" {
  display_name = "Slack Octo STS Notification"
}

locals {
  notification_channels = [
    data.google_monitoring_notification_channel.notify-chainguard-slack.name,
  ]
}

module "github-wif" {
  source  = "chainguard-dev/common/infra//modules/github-wif-provider"
  version = "0.6.92"

  project_id = var.project_id
  name       = "github-pool"

  notification_channels = local.notification_channels
}

moved {
  from = google_iam_workload_identity_pool.github_pool
  to   = module.github-wif.google_iam_workload_identity_pool.this
}

moved {
  from = google_iam_workload_identity_pool_provider.github_provider
  to   = module.github-wif.google_iam_workload_identity_pool_provider.this
}

module "github_identity" {
  source  = "chainguard-dev/common/infra//modules/github-gsa"
  version = "0.6.92"

  project_id = var.project_id
  name       = "github-identity"
  wif-pool   = module.github-wif.pool_name

  repository   = "octo-sts/app"
  refspec      = "refs/heads/main"
  workflow_ref = ".github/workflows/deploy.yaml"

  notification_channels = local.notification_channels
}

moved {
  from = google_service_account.github_identity
  to   = module.github_identity.google_service_account.this
}


resource "google_project_iam_member" "github_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${module.github_identity.email}"
}

module "github_pull_requests" {
  source  = "chainguard-dev/common/infra//modules/github-gsa"
  version = "0.6.92"

  project_id = var.project_id
  name       = "github-pull-requests"
  wif-pool   = module.github-wif.pool_name

  repository   = "octo-sts/app"
  refspec      = "pull_request"
  workflow_ref = ".github/workflows/verify-prod.yaml"

  notification_channels = local.notification_channels
}

moved {
  from = google_service_account.github_pull_requests
  to   = module.github_pull_requests.google_service_account.this
}

resource "google_project_iam_member" "github_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${module.github_pull_requests.email}"
}

resource "google_project_iam_member" "github_iam_viewer" {
  project = var.project_id
  role    = "roles/iam.securityReviewer"
  member  = "serviceAccount:${module.github_pull_requests.email}"
}
