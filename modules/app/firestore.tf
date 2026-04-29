// Firestore for persistent sticky routing (checks:write policies).
// Only created when var.sticky_store == "firestore".

resource "google_project_service" "firestore" {
  count   = var.sticky_store == "firestore" ? 1 : 0
  project = var.project_id
  service = "firestore.googleapis.com"

  disable_on_destroy = false
}

resource "google_firestore_database" "sticky" {
  count       = var.sticky_store == "firestore" ? 1 : 0
  project     = var.project_id
  name        = "(default)"
  location_id = "nam5"
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.firestore]
}

resource "google_firestore_field" "sticky_ttl" {
  count      = var.sticky_store == "firestore" ? 1 : 0
  project    = var.project_id
  database   = google_firestore_database.sticky[0].name
  collection = var.sticky_store_firestore_collection
  field      = "expire_at"

  ttl_config {}

  depends_on = [google_firestore_database.sticky]
}

resource "google_project_iam_member" "firestore_user" {
  count   = var.sticky_store == "firestore" ? 1 : 0
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.octo-sts.email}"
}
