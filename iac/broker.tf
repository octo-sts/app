// Create the Broker abstraction.
module "cloudevent-broker" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-broker"
  version = "0.4.20"

  name       = "octo-sts-broker"
  project_id = var.project_id
  regions    = module.networking.regional-networks

  notification_channels = local.notification_channels
}

module "cloudevent-recorder" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-recorder"
  version = "0.4.20"

  name       = "octo-sts-recorder"
  project_id = var.project_id
  regions    = module.networking.regional-networks
  broker     = module.cloudevent-broker.broker

  retention-period = 90

  provisioner = "serviceAccount:${data.google_client_openid_userinfo.me.email}"

  notification_channels = local.notification_channels

  types = {
    "dev.octo-sts.exchange" : {
      schema                = file("${path.module}/sts_exchange.schema.json")
      notification_channels = local.notification_channels
    }
  }
}
