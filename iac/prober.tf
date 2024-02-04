resource "google_service_account" "prober" {
  project    = var.project_id
  account_id = "octo-sts-prober"
}

module "prober" {
  source  = "chainguard-dev/common/infra//modules/prober"
  version = "0.4.4"

  name       = "octo-sts-prober"
  project_id = var.project_id
  regions    = module.networking.regional-networks
  egress     = "PRIVATE_RANGES_ONLY" // Talks to octos-sts via GCLB, and Github

  service_account = google_service_account.prober.email

  importpath  = "./cmd/prober"
  working_dir = "${path.module}/../"

  enable_alert = true
  // TODO(mattmoor): Wire up notifications once this is stable.
  // notification_channels = local.notification_channels
}

output "prober-sub" {
  value = google_service_account.octo-sts.unique_id
}
