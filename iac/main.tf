provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }
provider "ko" { repo = "gcr.io/${var.project_id}" }

// Create a network with several regional subnets
module "networking" {
  source  = "chainguard-dev/common/infra//modules/networking"
  version = "0.6.92"

  name          = var.name
  project_id    = var.project_id
  regions       = var.regions
  netnum_offset = 1
}

# For slack need to create the notification manually - https://github.com/hashicorp/terraform-provider-google/issues/11346
data "google_monitoring_notification_channel" "octo-sts-slack" {
  display_name = "Slack Octo STS Notification"
}

resource "ko_build" "this" {
  working_dir = "${path.module}/.."
  importpath  = "./cmd/app"
}

resource "cosign_sign" "this" {
  image    = ko_build.this.image_ref
  conflict = "REPLACE"
}

resource "ko_build" "webhook" {
  working_dir = "${path.module}/.."
  importpath  = "./cmd/webhook"
}

resource "cosign_sign" "webhook" {
  image    = ko_build.webhook.image_ref
  conflict = "REPLACE"
}

locals {
  notification_channels = [
    data.google_monitoring_notification_channel.octo-sts-slack.name
  ]
}

module "app" {
  source = "../modules/app"

  project_id = var.project_id
  name       = var.name
  regions    = module.networking.regional-networks

  private-services = {
    eventing-ingress = {
      name = module.cloudevent-broker.ingress.name
    }
  }

  domain = "octo-sts.dev"
  images = {
    app     = cosign_sign.this.signed_ref
    webhook = cosign_sign.webhook.signed_ref
  }

  github_app_id          = var.github_app_id
  github_app_key_version = 1
  notification_channels  = local.notification_channels
}
