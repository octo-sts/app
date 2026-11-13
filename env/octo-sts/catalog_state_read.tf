// Read-only access to this stack's Terraform state for the incident.io service
// catalog's state reader. The reader opens the state object by name and never
// lists the bucket, so it holds objectViewer on that one object and no list
// role: a list request names the bucket, not an object, so no condition on
// resource.name can match it.
resource "google_storage_bucket_iam_member" "catalog_state_read" {
  bucket = "octo-sts-terraform-state"
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:incident-io-catalog-state@eng-observability.iam.gserviceaccount.com"

  condition {
    title       = "catalog-state-read"
    description = "Read only this stack's Terraform state object. This grant carries no list permission."
    expression  = "resource.name == \"projects/_/buckets/octo-sts-terraform-state/objects/octo-sts/default.tfstate\""
  }
}
