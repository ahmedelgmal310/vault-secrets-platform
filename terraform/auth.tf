# Kubernetes auth: pods present a projected service account token with the
# audience "vault"; Vault validates it with the TokenReview API using its own
# service account (system:auth-delegator, granted by the Helm chart).
resource "vault_auth_backend" "kubernetes" {
  type        = "kubernetes"
  path        = "kubernetes"
  description = "Kubernetes service account login"
}

resource "vault_kubernetes_auth_backend_config" "this" {
  backend         = vault_auth_backend.kubernetes.path
  kubernetes_host = "https://kubernetes.default.svc:443"
  # Vault runs in the cluster: it reads the CA and its reviewer token from its
  # own pod, and re-reads the token as kubelet rotates it.
}

# Each role is bound to exactly one service account in one namespace.
resource "vault_kubernetes_auth_backend_role" "orders_api" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "orders-api"
  bound_service_account_names      = ["orders-api"]
  bound_service_account_namespaces = [var.app_namespace]
  audience                         = "vault"
  alias_name_source                = "serviceaccount_name"
  token_policies                   = [vault_policy.orders_api.name]
  token_ttl                        = 900
  token_max_ttl                    = 14400
  token_type                       = "service"
}

resource "vault_kubernetes_auth_backend_role" "eso_orders" {
  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "eso-orders"
  bound_service_account_names      = ["orders-eso"]
  bound_service_account_namespaces = [var.app_namespace]
  audience                         = "vault"
  alias_name_source                = "serviceaccount_name"
  token_policies                   = [vault_policy.eso_orders.name]
  token_ttl                        = 600
  token_max_ttl                    = 3600
  token_type                       = "service"
}
