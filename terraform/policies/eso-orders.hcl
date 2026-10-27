# eso-orders: External Secrets Operator acting for the orders namespace.
# It may read exactly one KV v2 secret and nothing else.
path "kv/data/orders-api/config" {
  capabilities = ["read"]
}
