// Generate a random webhook secret
resource "random_password" "webhook-secret" {
  length           = 64
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

module "webhook-secret" {
  source  = "chainguard-dev/common/infra//modules/configmap"
  version = "0.6.92"

  project_id = var.project_id
  name       = "${var.name}-webhook-secret"
  data       = random_password.webhook-secret.result

  service-account = google_service_account.octo-sts.email

  notification-channels = var.notification_channels
}

module "webhook" {
  source  = "chainguard-dev/common/infra//modules/regional-service"
  version = "0.6.92"

  project_id = var.project_id
  name       = "${var.name}-webhook"
  regions    = var.regions

  deletion_protection = var.deletion_protection

  // Only accept traffic coming from GCLB.
  ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  // This needs to egress in order to talk to Github
  egress = "PRIVATE_RANGES_ONLY"

  service_account = google_service_account.octo-sts.email
  containers = {
    "webhook" = {
      image = var.images.webhook
      ports = [{ container_port = 8080 }]
      env = [
        {
          name  = "GITHUB_APP_ID"
          value = var.github_app_id
        },
        {
          name  = "GITHUB_WEBHOOK_SECRET"
          value = module.webhook-secret.secret_version_id
        },
        {
          name  = "GITHUB_WEBHOOK_ORGANIZATION_FILTER"
          value = var.github_webhook_organization_filter
        },
        {
          name  = "KMS_KEY"
          value = local.kms_key
        }
      ]
    }
  }

  notification_channels = var.notification_channels
}
