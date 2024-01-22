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
