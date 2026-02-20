variable "project_id" {
  description = "The project ID where all resources created will reside."
}

variable "name" {
  description = "Name indicator, prefixed to resources created."
  default     = "octo-sts"
}

variable "regions" {
  description = "Regions where this environment's services should live."
  type        = list(string)
  default     = []
}

variable "github_apps" {
  description = "The GitHub Apps for the Octo STS service."
  type = list(object({
    app_id      = number
    key_version = number
  }))
}
