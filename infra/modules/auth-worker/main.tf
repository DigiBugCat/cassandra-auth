terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

resource "cloudflare_workers_kv_namespace" "credentials" {
  account_id = var.account_id
  title      = "${var.worker_script_name}-credentials"
}

resource "cloudflare_record" "worker" {
  zone_id = var.zone_id
  name    = var.worker_subdomain
  content = "${var.worker_script_name}.${var.account_id}.workers.dev"
  type    = "CNAME"
  proxied = true
  comment = "Cassandra auth service worker hostname"
}
