# Policies are plain HCL files so they can be reviewed in pull requests and
# linted by cmd/policylint (no wildcards, no sys/ or auth/, no sudo, unless an
# exception with a reason is written next to the path).
resource "vault_policy" "orders_api" {
  name   = "orders-api"
  policy = file("${path.module}/policies/orders-api.hcl")
}

resource "vault_policy" "eso_orders" {
  name   = "eso-orders"
  policy = file("${path.module}/policies/eso-orders.hcl")
}
