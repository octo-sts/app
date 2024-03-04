// Create the Broker abstraction.
module "cloudevent-broker" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-broker"
  version = "0.5.6"

  name       = "octo-sts-broker"
  project_id = var.project_id
  regions    = module.networking.regional-networks

  notification_channels = local.notification_channels
}

module "cloudevent-recorder" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-recorder"
  version = "0.5.6"

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

# TODO(mattmoor): We cannot use aggregations over expressions in materialized views.
# resource "google_bigquery_table" "errors-by-installations" {
#   dataset_id = module.cloudevent-recorder.dataset_id
#   table_id   = "errors_by_installations"

#   materialized_view {
#     query = <<EOT
#     SELECT installation_id,
#        (CASE WHEN STRPOS(scope, '/') > 0 THEN LEFT(scope, STRPOS(scope, '/')-1) ELSE scope END) as org,
#        AVG(CASE WHEN LENGTH(error) > 0 THEN 1 ELSE 0 END) * 100 as error_rate,
#        COUNT(*) as volume
#     FROM `${var.project_id}.${module.cloudevent-recorder.dataset_id}.${module.cloudevent-recorder.table_ids["dev.octo-sts.exchange"]}`
#     GROUP BY installation_id, org
#     EOT

#     enable_refresh      = true           # Automatically refresh this view when the underlying table changes.
#     refresh_interval_ms = 10 * 60 * 1000 # Maximum frequency at which this view will be refreshed.
#   }
# }
