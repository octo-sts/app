variable "project_id" {
  description = "The project ID where all resources created will reside."
}

variable "name" {
  description = "Name indicator, prefixed to resources created."
  default     = "enforce"
}

variable "regions" {
  description = "Tegions where this environment's services should live."
  type        = list(string)
  default     = []
}
