// Create the Broker abstraction.
module "cloudevent-broker" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-broker"
  version = "0.4.3"

  name       = "octo-sts"
  project_id = var.project_id
  regions    = module.networking.regional-networks
}
