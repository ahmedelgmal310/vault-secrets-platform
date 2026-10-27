# Two-tier PKI: an offline-style root that only signs the intermediate, and an
# intermediate that issues short-lived leaf certificates for orders-api.
resource "vault_mount" "pki_root" {
  path                  = "pki"
  type                  = "pki"
  description           = "Root CA"
  max_lease_ttl_seconds = 315360000 # 10 years
}

resource "vault_pki_secret_backend_root_cert" "root" {
  backend     = vault_mount.pki_root.path
  type        = "internal"
  common_name = "vault-secrets-platform Root CA"
  ttl         = "87600h"
  key_type    = "ec"
  key_bits    = 256
  issuer_name = "root-2026"
}

resource "vault_mount" "pki_int" {
  path                  = "pki_int"
  type                  = "pki"
  description           = "Intermediate CA for workload certificates"
  max_lease_ttl_seconds = 157680000 # 5 years
}

resource "vault_pki_secret_backend_intermediate_cert_request" "int" {
  backend     = vault_mount.pki_int.path
  type        = "internal"
  common_name = "vault-secrets-platform Intermediate CA"
  key_type    = "ec"
  key_bits    = 256
}

resource "vault_pki_secret_backend_root_sign_intermediate" "int" {
  backend     = vault_mount.pki_root.path
  csr         = vault_pki_secret_backend_intermediate_cert_request.int.csr
  common_name = "vault-secrets-platform Intermediate CA"
  ttl         = "43800h"
  format      = "pem_bundle"
  issuer_ref  = vault_pki_secret_backend_root_cert.root.issuer_id
}

resource "vault_pki_secret_backend_intermediate_set_signed" "int" {
  backend     = vault_mount.pki_int.path
  certificate = vault_pki_secret_backend_root_sign_intermediate.int.certificate
}

# The role pins the names orders-api may request; any other name is refused
# even though the policy allows the issue endpoint.
resource "vault_pki_secret_backend_role" "orders_api" {
  backend            = vault_mount.pki_int.path
  name               = "orders-api"
  allowed_domains    = ["orders-api.${var.app_namespace}.svc", "orders-api.${var.app_namespace}.svc.cluster.local"]
  allow_bare_domains = true
  allow_subdomains   = false
  allow_glob_domains = false
  allow_localhost    = false
  allow_ip_sans      = false
  enforce_hostnames  = true
  server_flag        = true
  client_flag        = false
  key_type           = "ec"
  key_bits           = 256
  ttl                = "120"
  max_ttl            = tostring(var.cert_max_ttl)
  # Short-lived certificates are not stored and not tracked by leases: they
  # expire before revocation would matter.
  no_store       = true
  generate_lease = false

  depends_on = [vault_pki_secret_backend_intermediate_set_signed.int]
}
