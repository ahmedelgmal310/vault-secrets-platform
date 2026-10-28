#!/usr/bin/env bash
# Applies the Vault configuration with Terraform, then rotates the database
# root credential so that only Vault knows the vault_admin password.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

vault_connect

log "terraform apply"
start="$(now)"
VAULT_TOKEN="$(jq -r .root_token "$VAULT_INIT_FILE")"
TF_VAR_db_admin_password="$(cat "$PRIVATE_DIR/vault-admin-password")"
export VAULT_TOKEN TF_VAR_db_admin_password
export TF_IN_AUTOMATION=1 TF_INPUT=0
terraform -chdir="$ROOT/terraform" init -input=false -lockfile=readonly > /dev/null
terraform -chdir="$ROOT/terraform" apply -auto-approve -input=false -no-color | tail -n 3
record terraform_apply_seconds "$(since "$start")"
record terraform_resources "$(terraform -chdir="$ROOT/terraform" state list | wc -l)"
record terraform_second_plan_changes "$(terraform -chdir="$ROOT/terraform" plan -detailed-exitcode -input=false -no-color > /dev/null && echo 0 || echo $?)"
unset VAULT_TOKEN

log "Rotating the database root credential (vault_admin)"
# Control: TCP logins are password-checked, so the bootstrap password works now
# and a wrong one does not.
pg_login vault_admin < "$PRIVATE_DIR/vault-admin-password" > /dev/null || fail "bootstrap password rejected before rotation"
if echo wrong-password | pg_login vault_admin > /dev/null; then fail "PostgreSQL accepts any password over TCP"; fi
vault POST database/rotate-root/orders-postgres -o /dev/null
# The password Terraform knew must no longer work.
if pg_login vault_admin < "$PRIVATE_DIR/vault-admin-password" > /dev/null; then
  fail "vault_admin still accepts the bootstrap password after rotate-root"
fi
record root_credential_rotated true
rm -f "$PRIVATE_DIR/vault-admin-password"

log "Mounted engines and auth methods"
vault GET sys/mounts | jq -r '.data | to_entries[] | select(.key | test("^(database|pki|pki_int|transit|kv)/$")) | "    \(.key)  \(.value.type)"'
vault GET sys/auth | jq -r '.data | to_entries[] | "    auth \(.key)  \(.value.type)"'
vault GET sys/audit | jq -r '.data | to_entries[] | "    audit \(.key)  \(.value.type)  \(.value.options.file_path)"'
