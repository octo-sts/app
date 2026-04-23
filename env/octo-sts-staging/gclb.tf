// This is imported from Cloud Domains
resource "google_dns_managed_zone" "top-level-zone" {
  project     = var.project_id
  name        = "octo-staging-dev"
  dns_name    = "octo-staging.dev."
  description = "DNS zone for domain: octo-staging.dev"

  dnssec_config {
    state = "on"
  }
}

// Put the above domain in front of our regional services.
module "serverless-gclb" {
  source  = "chainguard-dev/common/infra//modules/serverless-gclb"
  version = "1.0.2"

  team = "developer-platform"

  name       = var.name
  project_id = var.project_id
  dns_zone   = google_dns_managed_zone.top-level-zone.name

  // Regions are all of the places that we have backends deployed.
  // Regions must be removed from serving before they are torn down.
  regions         = keys(module.networking.regional-networks)
  serving_regions = keys(module.networking.regional-networks)

  public-services = {
    "octo-staging.dev" = {
      name = module.app.app.name
    }
    "webhook.octo-staging.dev" = {
      name = module.app.webhook.name
    }
  }
}
