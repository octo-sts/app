moved {
  from = module.app.google_dns_managed_zone.top-level-zone
  to   = google_dns_managed_zone.top-level-zone
}

moved {
  from = module.app.module.serverless-gclb
  to   = module.serverless-gclb
}

// This is imported from Cloud Domains
resource "google_dns_managed_zone" "top-level-zone" {
  project     = var.project_id
  name        = "octo-sts-dev"
  dns_name    = "octo-sts.dev."
  description = "DNS zone for domain: octo-sts.dev"

  dnssec_config {
    state = "on"
  }
}

// Put the above domain in front of our regional services.
module "serverless-gclb" {
  source  = "chainguard-dev/common/infra//modules/serverless-gclb"
  version = "1.72.0"

  team = "developer-platform"

  name       = var.name
  project_id = var.project_id
  dns_zone   = google_dns_managed_zone.top-level-zone.name

  // Regions are all of the places that we have backends deployed.
  // Regions must be removed from serving before they are torn down.
  regions         = keys(module.networking.regional-networks)
  serving_regions = keys(module.networking.regional-networks)

  // Preserve the Classic load balancer when upgrading the Google providers.
  forwarding_rule_load_balancing = {
    load_balancing_scheme = "EXTERNAL"
  }

  public-services = {
    "octo-sts.dev" = {
      name                  = module.app.app.name
      load_balancing_scheme = "EXTERNAL"
    }
    "webhook.octo-sts.dev" = {
      name                  = module.app.webhook.name
      load_balancing_scheme = "EXTERNAL"
    }
  }
}
