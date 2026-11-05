// The policy cleanup job proposes removing trust policies nobody has used, in
// organizations that opted in with an octo-sts-cleanup policy that trusts this
// service account. It reads only this deployment's exchange history. Staging
// keeps its policies in .github/chainguard-staging, so every policy in this
// deployment's directory is exchanged through this deployment.
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
  // `gcloud run jobs execute octo-sts-policy-cleanup-cron`.
  schedule = "0 15 1 * *"

  service_account = google_service_account.policy_cleanup.email

  importpath  = "./cmd/policy-cleanup"
  working_dir = "${path.module}/../../"

  // Listing policies costs a few GraphQL queries per org; an hour leaves
  // plenty of room. A failed run is retried once: publishing is idempotent.
  timeout     = "3600s"
  max_retries = 1

  env = {
    STS_DOMAIN = "octo-sts.dev"
    // Every App in var.github_apps, in the same order: 801323, 3000317,
    // 3017150, 3018136, 3018176, 3338961, 3339043, 3339085, 3339106 and
    // 3339139. Exchanges rotate across them, so keep this in step when an
    // App is added.
    GITHUB_APP_SLUGS = "octo-sts,octo-sts-2,octo-sts-3,octo-sts-4,octo-sts-5,octo-sts-6,octo-sts-7,octo-sts-8,octo-sts-9,octo-sts-10"
    EXCHANGE_TABLE   = "${var.project_id}.${module.cloudevent-recorder.dataset_id}.${module.cloudevent-recorder.table_ids["dev.octo-sts.exchange"]}"
    // Starts as a dry run: it only logs what it would remove until the first
    // runs' proposals have been reviewed.
    DRY_RUN = "true"
  }

  failed_execution_alert = true
  failed_execution_alert_documentation = join("\n", [
    "The policy cleanup job failed for at least one organization.",
    "Its logs name each organization and the error.",
  ])
  notification_channels = local.notification_channels
}
