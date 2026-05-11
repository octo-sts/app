// Firestore for persistent sticky routing (checks:write policies).
// Provisioned when sticky_store_firestore_collection is set. Operators on
// non-Firestore backends leave the collection empty and supply sticky_store_url.

locals {
  firestore_enabled = var.sticky_store_firestore_collection != ""

  # When the operator hasn't overridden the URL, derive it from the collection
  # so the URL and the provisioned TTL field policy refer to the same target.
  sticky_store_url = var.sticky_store_url != "" ? var.sticky_store_url : (
    local.firestore_enabled
    ? "firestore://projects/${var.project_id}/databases/(default)/documents/${var.sticky_store_firestore_collection}?name_field=key"
    : ""
  )
}

resource "google_project_service" "firestore" {
  count   = local.firestore_enabled ? 1 : 0
  project = var.project_id
  service = "firestore.googleapis.com"

  disable_on_destroy = false
}

resource "google_firestore_database" "sticky" {
  count       = local.firestore_enabled ? 1 : 0
  project     = var.project_id
  name        = "(default)"
  location_id = "nam5"
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.firestore]
}

resource "google_firestore_field" "sticky_ttl" {
  count      = local.firestore_enabled ? 1 : 0
  project    = var.project_id
  database   = google_firestore_database.sticky[0].name
  collection = var.sticky_store_firestore_collection
  field      = "expire_at"

  ttl_config {}

  depends_on = [google_firestore_database.sticky]
}

resource "google_project_iam_member" "firestore_user" {
  count   = local.firestore_enabled ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.octo-sts.email}"
}
