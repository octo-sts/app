variable "project_id" {
  description = "The project ID where all resources created will reside."
}

variable "name" {
  description = "Name indicator, prefixed to resources created."
}

variable "regions" {
  description = "Regions where this environment's services should live."
  type        = list(string)
}

variable "github_apps" {
  description = "The GitHub Apps for the Octo STS service, with optional org_name for organization pools and app_name for trust policy app/app_pattern selectors. Named apps require org_name on every app (use \"*\" for a fallback pool)."
  type = list(object({
    app_id      = number
    key_version = number
    org_name    = optional(string, "")
    app_name    = optional(string, "")
  }))
}
