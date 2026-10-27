# Transit: encryption as a service. The key cannot be exported or deleted.
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "Encryption as a service"
}

resource "vault_transit_secret_backend_key" "orders" {
  backend          = vault_mount.transit.path
  name             = "orders"
  type             = "aes256-gcm96"
  exportable       = false
  deletion_allowed = false
}

# KV v2 for static secrets that External Secrets Operator syncs into
# Kubernetes. Values are written by operators (CI here), not by Terraform, so
# rotating a value is not drift.
resource "vault_mount" "kv" {
  path        = "kv"
  type        = "kv"
  options     = { version = "2" }
  description = "Static secrets"
}

# File audit device on the audit PVC. Every request and response is logged
# with secret values HMAC-ed, including denied requests.
resource "vault_audit" "file" {
  type        = "file"
  path        = "file"
  description = "File audit log"
  options = {
    file_path = "/vault/audit/audit.log"
  }
}
