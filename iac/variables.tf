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

variable "github_app_ids" {
  description = "The Github App ID for the Octo STS service."
  type        = list(number)
}
