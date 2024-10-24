// Create the Broker abstraction.
module "cloudevent-broker" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-broker"
  version = "0.6.92"

  name       = "octo-sts-broker"
  project_id = var.project_id
  regions    = module.networking.regional-networks

  notification_channels = local.notification_channels
}

data "google_client_openid_userinfo" "me" {}

module "cloudevent-recorder" {
  source  = "chainguard-dev/common/infra//modules/cloudevent-recorder"
  version = "0.6.92"

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

resource "google_bigquery_table" "errors-by-installations" {
  dataset_id = module.cloudevent-recorder.dataset_id
  table_id   = "errors_by_installations"

  view {
    query = <<EOT
    SELECT installation_id,
       (CASE WHEN STRPOS(scope, '/') > 0 THEN LEFT(scope, STRPOS(scope, '/')-1) ELSE scope END) as org,
       TIMESTAMP_TRUNC(_PARTITIONTIME, DAY) as day,
       AVG(CASE WHEN LENGTH(error) > 0 THEN 1 ELSE 0 END) * 100 as error_rate,
       COUNT(*) as volume
    FROM `${var.project_id}.${module.cloudevent-recorder.dataset_id}.${module.cloudevent-recorder.table_ids["dev.octo-sts.exchange"]}`
    GROUP BY installation_id, org, day
    EOT
    // Use standard SQL
    use_legacy_sql = false
  }
}

resource "google_bigquery_table" "errors-by-subject" {
  dataset_id = module.cloudevent-recorder.dataset_id
  table_id   = "errors_by_subject"

  view {
    query = <<EOT
    SELECT actor.sub as subject,
       TIMESTAMP_TRUNC(_PARTITIONTIME, DAY) as day,
       AVG(CASE WHEN LENGTH(error) > 0 THEN 1 ELSE 0 END) * 100 as error_rate,
       COUNT(*) as volume
    FROM `${var.project_id}.${module.cloudevent-recorder.dataset_id}.${module.cloudevent-recorder.table_ids["dev.octo-sts.exchange"]}`
    GROUP BY subject, day
    EOT
    // Use standard SQL
    use_legacy_sql = false
  }
}
