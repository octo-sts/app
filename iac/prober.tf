resource "google_service_account" "prober" {
  project    = var.project_id
  account_id = "octo-sts-prober"
}

module "prober" {
  source  = "chainguard-dev/common/infra//modules/prober"
  version = "0.6.92"

  name       = "octo-sts-prober"
  project_id = var.project_id
  regions    = module.networking.regional-networks
  egress     = "PRIVATE_RANGES_ONLY" // Talks to octos-sts via GCLB, and Github

  service_account = google_service_account.prober.email

  importpath  = "./cmd/prober"
  working_dir = "${path.module}/../"

  env = {
    STS_DOMAIN = "octo-sts.dev"
  }

  enable_alert          = true
  notification_channels = local.notification_channels
}

resource "google_service_account" "negative_prober" {
  project    = var.project_id
  account_id = "octo-sts-negative-prober"
}

module "negative_prober" {
  source  = "chainguard-dev/common/infra//modules/prober"
  version = "0.6.92"

  name       = "octo-sts-negative-prober"
  project_id = var.project_id
  regions    = module.networking.regional-networks
  egress     = "PRIVATE_RANGES_ONLY" // Talks to octos-sts via GCLB, and Github

  service_account = google_service_account.negative_prober.email

  importpath  = "./cmd/negative-prober"
  working_dir = "${path.module}/../"

  env = {
    STS_DOMAIN = "octo-sts.dev"
  }

  enable_alert          = true
  notification_channels = local.notification_channels
}

module "dashboard" {
  source       = "chainguard-dev/common/infra//modules/dashboard/service"
  version      = "0.6.92"
  service_name = var.name
  project_id   = var.project_id

  alerts = {
    "STS Probe" : module.prober.alert_id,
    "STS Negative Probe" : module.negative_prober.alert_id
  }

  notification_channels = local.notification_channels
}
