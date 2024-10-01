variable "project_id" {
  description = "The project ID where all resources created will reside."
}

variable "name" {
  description = "Name indicator, prefixed to resources created."
  default     = "octo-sts"
}

variable "regions" {
  description = "A map from region names to a network and subnetwork.  A service will be created in each region configured to egress the specified traffic via the specified subnetwork."
  type = map(object({
    network = string
    subnet  = string
  }))
}

variable "deletion_protection" {
  type        = bool
  description = "Whether to enable delete protection for the service."
  default     = true
}

variable "private-services" {
  description = "The names of the private services this module depends on."
  type = object({
    eventing-ingress = object({
      name = string
    })
  })
}

variable "domain" {
  description = "The domain that this instance serves on."
  type        = string
}

variable "images" {
  description = "The Octo STS application image."
  type = object({
    app     = optional(string, "chainguard/octo-sts:latest")
    webhook = optional(string, "chainguard/octo-sts-webhook:latest")
  })
  default = {
    app     = "chainguard/octo-sts:latest"
    webhook = "chainguard/octo-sts-webhook:latest"
  }
}

variable "github_app_id" {
  description = "The identifier for the GitHub App."
  type        = number
}

variable "github_app_key_version" {
  description = "The version number of the signing key loaded into KMS."
  type        = number
}

variable "notification_channels" {
  description = "List of notification channels to alert."
  type        = list(string)
}

variable "github_webhook_organization_filter" {
  description = "The organizations to filter webhook events on (comma separated)."
  type        = string
  default     = ""
}
