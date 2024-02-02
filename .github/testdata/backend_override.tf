terraform {
  backend "local" {
    path = "./.local-state"
  }
  required_providers {
    ko = { source = "ko-build/ko" }
  }
}
