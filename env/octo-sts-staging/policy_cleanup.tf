// The policy cleanup job proposes removing trust policies nobody has used, in
// organizations that opted in with an octo-sts-cleanup policy that trusts this
// service account. It reads only this deployment's exchange history, so it
// must only see this deployment's policies (see policy_dir in main.tf).
resource "google_service_account" "policy_cleanup" {
  project      = var.project_id
  account_id   = "octo-sts-policy-cleanup"
  display_name = "Octo STS policy cleanup"
}

// Read this deployment's exchange history, and nothing else.
resource "google_bigquery_dataset_iam_member" "policy_cleanup_reads_exchanges" {
  project    = var.project_id
  dataset_id = module.cloudevent-recorder.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.policy_cleanup.email}"
}

resource "google_project_iam_member" "policy_cleanup_runs_queries" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.policy_cleanup.email}"
}

module "policy_cleanup" {
  source  = "chainguard-dev/common/infra//modules/cron"
  version = "1.72.1"

  team = "developer-platform"

  name       = "octo-sts-policy-cleanup"
  project_id = var.project_id
  region     = var.regions[0]

  // 15:00 UTC on the first of each month. Run it by hand with
  // `gcloud run jobs execute octo-sts-policy-cleanup`.
  schedule = "0 15 1 * *"

  service_account = google_service_account.policy_cleanup.email

  importpath  = "./cmd/policy-cleanup"
  working_dir = "${path.module}/../../"

  // Listing policies costs a few GraphQL queries per org; an hour leaves
  // plenty of room. A failed run is retried once: publishing is idempotent.
  timeout     = "3600s"
  max_retries = 1

  env = {
    STS_DOMAIN = "octo-staging.dev"
    // Every App in var.github_apps: 2991343 and 3000098.
    GITHUB_APP_SLUGS   = "octo-sts-staging,octo-sts-staging-2"
    EXCHANGE_TABLE     = "${var.project_id}.${module.cloudevent-recorder.dataset_id}.${module.cloudevent-recorder.table_ids["dev.octo-sts.exchange"]}"
    OCTOSTS_POLICY_DIR = ".github/chainguard-staging"
    // Staging only ever logs what it would do.
    DRY_RUN = "true"
  }

  failed_execution_alert = true
  failed_execution_alert_documentation = join("\n", [
    "The policy cleanup job failed for at least one organization.",
    "Its logs name each organization and the error.",
  ])
  notification_channels = local.notification_channels
}
