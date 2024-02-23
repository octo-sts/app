module "webhook-service" {
  source  = "chainguard-dev/common/infra//modules/regional-go-service"
  version = "0.5.2"

  project_id = var.project_id
  name       = var.name
  regions    = module.networking.regional-networks

  // Only accept traffic coming from GCLB.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  // This needs to egress in order to talk to Github
  egress = "PRIVATE_RANGES_ONLY"

  service_account = google_service_account.octo-sts.email
  containers = {
    "webhook" = {
      source = {
        working_dir = "${path.module}/.."
        importpath  = "./cmd/webhook"
      }
      ports = [{ container_port = 8080 }]
      env = [
        {
          name  = "GITHUB_APP_ID"
          value = var.github_app_id
        },
        {
          name  = "GITHUB_WEBHOOK_SECRET"
          value = google_secret_manager_secret.github-webhook.secret_id
        },
        {
          name  = "KMS_KEY"
          value = local.kms_key
        }
      ]
    }
  }

  notification_channels = local.notification_channels
}

resource "google_secret_manager_secret" "github-webhook" {
  secret_id = "github-webhook"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_iam_binding" "github-webhook" {
  secret_id = google_secret_manager_secret.github-webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  members = [
    "serviceAccount:${google_service_account.octo-sts.email}",
  ]
}
