output "credentials_kv_namespace_id" {
  description = "KV namespace ID for per-user credentials"
  value       = cloudflare_workers_kv_namespace.credentials.id
}

output "worker_hostname" {
  description = "Public Worker hostname"
  value       = "${var.worker_subdomain}.${var.domain}"
}

output "auth_url" {
  description = "Auth service base URL"
  value       = "https://${var.worker_subdomain}.${var.domain}"
}
