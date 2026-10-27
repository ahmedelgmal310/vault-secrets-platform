output "database_creds_path" {
  description = "Path that issues dynamic PostgreSQL credentials."
  value       = "${vault_mount.database.path}/creds/${vault_database_secret_backend_role.orders_api.name}"
}

output "database_connection" {
  description = "Name of the database connection (for rotate-root)."
  value       = vault_database_secret_backend_connection.postgres.name
}

output "pki_issue_path" {
  description = "Path that issues orders-api TLS certificates."
  value       = "${vault_mount.pki_int.path}/issue/${vault_pki_secret_backend_role.orders_api.name}"
}

output "kubernetes_roles" {
  description = "Kubernetes auth roles."
  value       = [vault_kubernetes_auth_backend_role.orders_api.role_name, vault_kubernetes_auth_backend_role.eso_orders.role_name]
}
