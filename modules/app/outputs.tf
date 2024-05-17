output "nameservers" {
  value = google_dns_managed_zone.top-level-zone.name_servers
}
