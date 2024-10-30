resource "google_dns_record_set" "github_verify" {
  managed_zone = google_dns_managed_zone.top-level-zone.name

  name         = "_gh-octo-sts-o.octo-sts.dev."
  type         = "TXT"
  ttl          = 300

  rrdatas = [
    "\"cc539450df\"",
  ]
}
