output "app" {
  depends_on = [module.this]
  value = {
    name = var.name
  }
}

output "webhook" {
  depends_on = [module.webhook]
  value = {
    name = "${var.name}-webhook"
  }
}
