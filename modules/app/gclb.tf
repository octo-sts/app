// This is imported from Cloud Domains
resource "google_dns_managed_zone" "top-level-zone" {
  project     = var.project_id
  name        = "octo-sts-dev"
  dns_name    = "${var.domain}."
  description = "DNS zone for domain: ${var.domain}"

  dnssec_config {
    state = "on"
  }
}

// Put the above domain in front of our regional services.
module "serverless-gclb" {
  source  = "chainguard-dev/common/infra//modules/serverless-gclb"
  version = "0.6.18"

  name       = var.name
  project_id = var.project_id
  dns_zone   = google_dns_managed_zone.top-level-zone.name

  // Regions are all of the places that we have backends deployed.
  // Regions must be removed from serving before they are torn down.
  regions         = keys(var.regions)
  serving_regions = keys(var.regions)

  public-services = {
    "${var.domain}" = {
      name = var.name
    }
  }
}
