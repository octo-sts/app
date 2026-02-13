# Copyright 2026 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

module "octo_sts" {
  source = "../../iac"

  project_id    = var.project_id
  name          = var.name
  regions       = var.regions
  github_app_id = var.github_app_id
}
