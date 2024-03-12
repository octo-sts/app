provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }

resource "google_project_service" "iamcredentials-api" {
  project                    = var.project_id
  service                    = "iamcredentials.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}

resource "google_iam_workload_identity_pool" "github_pool" {
  project                   = var.project_id
  provider                  = google-beta
  workload_identity_pool_id = "github-pool"
  display_name              = "Github pool"
  depends_on                = [google_project_service.iamcredentials-api]
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  project                            = var.project_id
  provider                           = google-beta
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider" # This gets 4-32 alphanumeric characters (and '-')
  display_name                       = "Github provider"

  attribute_mapping = {
    "google.subject" = "assertion.sub"
    "attribute.sub"  = "assertion.sub"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "github_identity" {
  project    = var.project_id
  account_id = "github-identity"
}

resource "google_service_account_iam_binding" "allow_github_impersonation" {
  service_account_id = google_service_account.github_identity.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.sub/repo:octo-sts/app:ref:refs/heads/main",
  ]
}

resource "google_project_iam_member" "github_owner" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.github_identity.email}"
}

resource "google_service_account" "github_pull_requests" {
  project    = var.project_id
  account_id = "github-pull-requests"
}

resource "google_service_account_iam_binding" "allow_github_pull_requests_impersonation" {
  service_account_id = google_service_account.github_pull_requests.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.sub/repo:octo-sts/app:pull_request",
  ]
}

resource "google_project_iam_member" "github_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.github_pull_requests.email}"
}
