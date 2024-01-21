terraform {
  backend "gcs" {
    bucket = "octo-sts-terraform-state"
    prefix = "/octo-sts"
    # bucket = "mattmoor-chainguard-terraform-state"
    # prefix = "/octo-sts"
  }
  required_providers {
    ko = { source = "ko-build/ko" }
  }
}

provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }
provider "ko" { docker_repo = "gcr.io/${var.project_id}" }

// Create a network with several regional subnets
module "networking" {
  source = "chainguard-dev/common/infra//modules/networking"

  name       = var.name
  project_id = var.project_id
  regions    = var.regions
}

// Create a keyring to hold our OIDC keys.
resource "google_kms_key_ring" "app-keyring" {
  project  = var.project_id
  name     = var.name
  location = "global"
}

// Create an asymmetric signing key to use for signing tokens.
resource "google_kms_crypto_key" "app-key" {
  name     = "app-signing-key"
  key_ring = google_kms_key_ring.app-keyring.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "RSA_SIGN_PKCS1_2048_SHA256"
  }

  import_only                   = true
  skip_initial_version_creation = true
}

locals {
  # To import a key, we need to run the following commands:
  # gcloud kms import-jobs create app-import-job \
  #   --location global \
  #   --keyring octo-sts \
  #   --import-method rsa-oaep-4096-sha256-aes-256 \
  #   --protection-level software

  # gcloud kms import-jobs describe app-import-job \
  #   --location global \
  #   --keyring octo-sts \
  #   --format="value(state)"

  # openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER \
  #     -in key.pem -out key.data

  # # Needs: pip3 install --user "cryptography>=2.2.0"
  # CLOUDSDK_PYTHON_SITEPACKAGES=1 gcloud kms keys versions import \
  #     --import-job app-import-job \
  #     --location global \
  #     --keyring octo-sts \
  #     --key app-signing-key \
  #     --algorithm rsa-sign-pkcs1-2048-sha256 \
  #     --target-key-file key.data
  kms_key = "${google_kms_crypto_key.app-key.id}/cryptoKeyVersions/1"
}

// Create a dedicated GSA for the IAM datastore service.
resource "google_service_account" "octo-sts" {
  project = var.project_id

  account_id   = var.name
  display_name = "Octo STS"
  description  = "Dedicated service account for the Octo STS service."
}

// Allow the STS service to call the sign method on the keys in the keyring.
resource "google_kms_key_ring_iam_binding" "signer-members" {
  key_ring_id = google_kms_key_ring.app-keyring.id
  role        = "roles/cloudkms.signer"
  members = [
    "serviceAccount:${google_service_account.octo-sts.email}",
  ]
}

module "sts-service" {
  source = "chainguard-dev/common/infra//modules/regional-go-service"

  project_id = var.project_id
  name       = var.name
  regions    = module.networking.regional-networks

  // TODO: Put this behind GCLB
  ingress = "INGRESS_TRAFFIC_ALL"
  // This needs to egress in order to talk to Github
  egress = "PRIVATE_RANGES_ONLY"

  service_account = google_service_account.octo-sts.email
  containers = {
    "sts" = {
      source = {
        working_dir = "${path.module}/.."
        importpath  = "./cmd/app"
      }
      ports = [{ container_port = 8080 }]
      env = [
        {
          name  = "GITHUB_APP_ID"
          value = "801323" // https://github.com/settings/apps/octosts
        },
        {
          name  = "KMS_KEY"
          value = local.kms_key
        }
      ]
    }
  }
}

// TODO: Remove this when we shift the above to be behind GCLB.
resource "google_cloud_run_v2_service_iam_member" "public-services-are-unauthenticated" {
  for_each = module.networking.regional-networks

  // Ensure that the service exists before attempting to expose things publicly.
  depends_on = [module.sts-service]

  project  = var.project_id
  location = each.key
  name     = var.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
