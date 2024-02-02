// Create the Broker abstraction.
module "cloudevent-broker" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-broker"
  version = "0.4.3"

  name       = "octo-sts-broker"
  project_id = var.project_id
  regions    = module.networking.regional-networks
}

module "cloudevent-recorder" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-recorder"
  version = "0.4.3"

  name       = "octo-sts-recorder"
  project_id = var.project_id
  regions    = module.networking.regional-networks
  broker     = module.cloudevent-broker.broker

  retention-period = 90

  provisioner = "serviceAccount:${data.google_client_openid_userinfo.me.email}"

  types = {
    "dev.octo-sts.exchange": {
      schema = file("${path.module}/sts_exchange.schema.json")
    }
  }
}
