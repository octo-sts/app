provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }
provider "ko" { docker_repo = "gcr.io/${var.project_id}" }

// Create a network with several regional subnets
module "networking" {
  source  = "chainguard-dev/common/infra//modules/networking"
  version = "0.5.4"

  name          = var.name
  project_id    = var.project_id
  regions       = var.regions
  netnum_offset = 1
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

# For slack need to create the notification manually - https://github.com/hashicorp/terraform-provider-google/issues/11346
data "google_monitoring_notification_channel" "octo-sts-slack" {
  display_name = "Slack Octo STS Notification"
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

  notification_channels = [
    data.google_monitoring_notification_channel.octo-sts-slack.name
  ]
}

// Create a dedicated GSA for the IAM datastore service.
resource "google_service_account" "octo-sts" {
  project = var.project_id

  account_id   = var.name
  display_name = "Octo STS"
  description  = "Dedicated service account for the Octo STS service."
}

// Authorize the "octo-sts" service account to publish events.
module "sts-emits-events" {
  for_each = module.networking.regional-networks

  source = "chainguard-dev/common/infra//modules/authorize-private-service"

  project_id = var.project_id
  region     = each.key
  name       = module.cloudevent-broker.ingress.name

  service-account = google_service_account.octo-sts.email
}

module "sts-service" {
  source  = "chainguard-dev/common/infra//modules/regional-go-service"
  version = "0.5.4"

  project_id = var.project_id
  name       = var.name
  regions    = module.networking.regional-networks

  // Only accept traffic coming from GCLB.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
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
      regional-env = [{
        name  = "EVENT_INGRESS_URI"
        value = { for k, v in module.sts-emits-events : k => v.uri }
      }]
    }
  }

  notification_channels = local.notification_channels
}

module "dashboard" {
  source       = "chainguard-dev/common/infra//modules/dashboard/service"
  version      = "0.5.4"
  service_name = var.name
  project_id   = var.project_id

  alerts = {
    "STS Probe" : module.prober.alert_id,
    "STS Negative Probe" : module.negative_prober.alert_id
  }

  notification_channels = local.notification_channels
}

// Allow the STS service to call the sign method on the keys in the keyring.
resource "google_kms_key_ring_iam_binding" "signer-members" {
  key_ring_id = google_kms_key_ring.app-keyring.id
  role        = "roles/cloudkms.signer"
  members = [
    "serviceAccount:${google_service_account.octo-sts.email}",
  ]
}

data "google_client_openid_userinfo" "me" {}

resource "google_monitoring_alert_policy" "anomalous-kms-access" {
  # In the absence of data, incident will auto-close after an hour
  alert_strategy {
    auto_close = "3600s"

    notification_rate_limit {
      period = "3600s" // re-alert hourly if condition still valid.
    }
  }

  display_name = "Abnormal KMS Access"
  combiner     = "OR"

  conditions {
    display_name = "Unauthorized KMS access"

    condition_matched_log {
      filter = <<EOT
      -- KMS operations
      protoPayload.serviceName="cloudkms.googleapis.com"

      -- Against our Github App's keyring
      protoPayload.resourceName: "${google_kms_key_ring.app-keyring.id}/"

      -- The application itself should only perform signing operations.
      -(
        protoPayload.authenticationInfo.principalEmail="${google_service_account.octo-sts.email}" AND
        protoPayload.methodName=("AsymmetricSign")
      )

      -- Github IaC should only reconcile the keyring and keys.
      -(
        protoPayload.authenticationInfo.principalEmail="${data.google_client_openid_userinfo.me.email}" AND
        protoPayload.methodName=("CreateKeyRing" OR "CreateCryptoKey" OR "GetCryptoKey" OR "SetIamPolicy")
      )

      -- If we were to filter out import events they would look like
      -- this, but instead I am opting to explicitly have these alert,
      -- to raise awareness of the rotation, since it means that a human
      -- has interacted with an App key locally.
      -- -(
      --   protoPayload.authenticationInfo.principalEmail="...@chainguard.dev" AND
      --   protoPayload.methodName=("CreateImportJob" OR "ImportCryptoKeyVersion")
      -- )
      EOT
    }
  }

  notification_channels = local.notification_channels

  enabled = "true"
  project = var.project_id
}
