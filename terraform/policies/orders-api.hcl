# orders-api: the only identity that may obtain orders database credentials,
# certificates for orders-api.orders.svc and use the "orders" transit key.
# Token self-management and sys/leases/renew come from Vault's default policy.

# Dynamic PostgreSQL credentials (database secrets engine, role orders-api).
path "database/creds/orders-api" {
  capabilities = ["read"]
}

# policylint:allow wildcard,privileged-path -- revoke is scoped to leases issued by database/creds/orders-api; lease ids are unguessable
path "sys/leases/revoke/database/creds/orders-api/*" {
  capabilities = ["update"]
}

# Short-lived TLS server certificates. The PKI role restricts the names.
path "pki_int/issue/orders-api" {
  capabilities = ["update"]
}

# Encryption as a service with one named key; no key export, no rotation.
path "transit/encrypt/orders" {
  capabilities = ["update"]
}

path "transit/decrypt/orders" {
  capabilities = ["update"]
}
