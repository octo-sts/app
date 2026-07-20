// Create a keyring to hold our GitHub App keys.
resource "google_kms_key_ring" "app-keyring" {
  project  = var.project_id
  name     = var.name
  location = "global"
}

// Existing prod key, which will be deleted after migration to multi app.
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

// Create a separate asymmetric signing key for each GitHub App.
resource "google_kms_crypto_key" "app-keys" {
  for_each = { for app in var.github_apps : tostring(app.app_id) => app if app.key_version > 0 }

  name     = "app-signing-key-${each.key}"
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
  kms_keys = [for app in var.github_apps : app.key_version > 0 ? "${google_kms_crypto_key.app-keys[tostring(app.app_id)].id}/cryptoKeyVersions/${app.key_version}" : ""]
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
  for_each = var.regions

  source  = "chainguard-dev/common/infra//modules/authorize-private-service"
  version = "1.21.0"

  project_id = var.project_id
  region     = each.key
  name       = var.private-services.eventing-ingress.name

  service-account = google_service_account.octo-sts.email
}

module "this" {
  source  = "chainguard-dev/common/infra//modules/regional-service"
  version = "1.21.0"

  team = "developer-platform"

  project_id = var.project_id
  name       = var.name
  regions    = var.regions

  deletion_protection = var.deletion_protection

  // Only accept traffic coming from GCLB.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  // This needs to egress in order to talk to Github
  egress = "PRIVATE_RANGES_ONLY"

  service_account = google_service_account.octo-sts.email
  containers = {
    "sts" = {
      image = var.images.app
      ports = [{ container_port = 8080 }]
      env = [
        {
          name  = "GITHUB_APP_IDS"
          value = join(",", [for app in var.github_apps : app.app_id])
        },
        {
          name  = "KMS_KEYS"
          value = join(",", local.kms_keys)
        },
        {
          name  = "STS_DOMAIN",
          value = var.domain,
        },
        {
          name  = "OCTOSTS_STICKY_STORE"
          value = var.sticky_store
        },
        {
          name  = "OCTOSTS_STICKY_STORE_FIRESTORE_PROJECT"
          value = var.sticky_store == "firestore" ? var.project_id : ""
        },
        {
          name  = "OCTOSTS_STICKY_STORE_FIRESTORE_COLLECTION"
          value = var.sticky_store_firestore_collection
        },
        {
          name  = "OCTOSTS_STICKY_STORE_FIRESTORE_TTL"
          value = var.sticky_store_firestore_ttl
        },
      ]
      regional-env = [{
        name  = "EVENT_INGRESS_URI"
        value = { for k, v in module.sts-emits-events : k => v.uri }
      }]
    }
  }

  notification_channels = var.notification_channels
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

resource "google_monitoring_alert_policy" "github-rate-limit" {
  alert_strategy {
    auto_close = "3600s" // auto close after an hour.

    notification_rate_limit {
      period = "3600s" // re-alert hourly if condition still valid.
    }
  }

  display_name = "GitHub API Rate Limit"
  combiner     = "OR"

  conditions {
    display_name = "GitHub API rate limit exceeded"

    condition_matched_log {
      filter = <<EOT
      resource.type="cloud_run_revision"
      resource.labels.service_name="${var.name}"
      textPayload=~"API rate limit exceeded"
      EOT
    }
  }

  notification_channels = var.notification_channels

  enabled = "true"
  project = var.project_id
}

resource "google_monitoring_alert_policy" "anomalous-kms-access" {
  alert_strategy {
    auto_close = "3600s" // auto close after an hour.

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

      -- Skip operations that are a part of terraform plan
      -protoPayload.methodName=("GetCryptoKey")

      -- Skip operations done by some infra scanners, which are harmless.
      -protoPayload.methodName=("GetIamPolicy")

      -- The application itself should only perform signing operations.
      -(
        protoPayload.authenticationInfo.principalEmail="${google_service_account.octo-sts.email}" AND
        protoPayload.methodName=("AsymmetricSign")
      )

      -- Github IaC should only reconcile the keyring and keys.
      -(
        protoPayload.authenticationInfo.principalEmail="${data.google_client_openid_userinfo.me.email}" AND
        protoPayload.methodName=("CreateKeyRing" OR "CreateCryptoKey" OR "SetIamPolicy")
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

      label_extractors = {
        "email"       = "EXTRACT(protoPayload.authenticationInfo.principalEmail)"
        "method_name" = "EXTRACT(protoPayload.methodName)"
        "user_agent"  = "REGEXP_EXTRACT(protoPayload.requestMetadata.callerSuppliedUserAgent, \"(\\\\S+)\")"
      }
    }
  }

  notification_channels = var.notification_channels

  enabled = "true"
  project = var.project_id
}

resource "google_logging_metric" "trust-policy-not-found" {
  project = var.project_id
  name    = "${var.name}-trust-policy-not-found"

  filter = <<EOT
  resource.type="cloud_run_revision"
  resource.labels.service_name="${var.name}"
  textPayload=~"negative cache hit"
  -textPayload=~"negative cache hit for {octo-sts prober does-not-exist}"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"

    labels {
      key         = "identity"
      value_type  = "STRING"
      description = "The trust policy identity that was not found"
    }
  }

  label_extractors = {
    "identity" = "REGEXP_EXTRACT(textPayload, \"negative cache hit for \\\\{\\\\S+ \\\\S+ (\\\\S+)\\\\}\")"
  }
}

resource "google_monitoring_alert_policy" "trust-policy-not-found" {
  project      = var.project_id
  display_name = "Trust Policy Not Found (>200/hr)"
  combiner     = "OR"

  alert_strategy {
    auto_close = "3600s"
  }

  conditions {
    display_name = "Trust policy negative cache hits exceed 200/hr"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.trust-policy-not-found.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 200
      duration        = "0s"

      aggregations {
        alignment_period     = "3600s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.labels.identity"]
      }
    }
  }

  documentation {
    content   = "Trust policy identity `$${metric.labels.identity}` has exceeded 200 negative cache hits in the last hour."
    mime_type = "text/markdown"
  }

  notification_channels = var.notification_channels
  enabled               = true
}
