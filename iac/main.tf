provider "google" { project = var.project_id }
provider "google-beta" { project = var.project_id }
provider "ko" { docker_repo = "gcr.io/${var.project_id}" }

// Create a network with several regional subnets
module "networking" {
  source  = "chainguard-dev/common/infra//modules/networking"
  version = "0.6.18"

  name          = var.name
  project_id    = var.project_id
  regions       = var.regions
  netnum_offset = 1
}

# For slack need to create the notification manually - https://github.com/hashicorp/terraform-provider-google/issues/11346
data "google_monitoring_notification_channel" "octo-sts-slack" {
  display_name = "Slack Octo STS Notification"
}

// Build each of the application images from source.
resource "ko_build" "this" {
  working_dir = "${path.module}/.."
  importpath  = "./cmd/app"
}

resource "cosign_sign" "this" {
  image    = ko_build.this.image_ref
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
  image  = cosign_sign.this.signed_ref

  github_app_id          = 801323 // https://github.com/settings/apps/octosts
  github_app_key_version = 1
  notification_channels  = local.notification_channels
}
