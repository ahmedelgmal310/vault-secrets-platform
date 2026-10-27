# Database secrets engine: every read of database/creds/orders-api creates a
# brand-new PostgreSQL role with a random password and a short lease.
resource "vault_mount" "database" {
  path        = "database"
  type        = "database"
  description = "Dynamic PostgreSQL credentials"
}

resource "vault_database_secret_backend_connection" "postgres" {
  backend           = vault_mount.database.path
  name              = "orders-postgres"
  allowed_roles     = ["orders-api"]
  verify_connection = true

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@${var.postgres_host}:5432/app?sslmode=disable"
    username       = "vault_admin"
    password       = var.db_admin_password
  }

  lifecycle {
    # e2e/configure.sh calls database/rotate-root right after apply, so the
    # password in state is stale by design and must not be re-applied.
    ignore_changes = [postgresql[0].password]
  }
}

resource "vault_database_secret_backend_role" "orders_api" {
  backend     = vault_mount.database.path
  name        = "orders-api"
  db_name     = vault_database_secret_backend_connection.postgres.name
  default_ttl = var.db_default_ttl
  max_ttl     = var.db_max_ttl

  # VALID UNTIL makes PostgreSQL itself reject the password after expiry, as a
  # second line of defence behind Vault's revocation.
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}' INHERIT;",
    "GRANT orders_app TO \"{{name}}\";",
  ]

  # Kill live sessions first, then drop the role: revoked credentials stop
  # working immediately, not just for new connections.
  revocation_statements = [
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
    "DROP ROLE IF EXISTS \"{{name}}\";",
  ]

  renew_statements = [
    "ALTER ROLE \"{{name}}\" VALID UNTIL '{{expiration}}';",
  ]
}
