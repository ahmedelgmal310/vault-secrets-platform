#!/usr/bin/env bash
# Proves External Secrets Operator sync: a KV v2 secret appears as a
# Kubernetes Secret, and a rotated value propagates within seconds.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

vault_connect

# write_kv FILE: write kv/data/orders-api/config with api_key from FILE.
write_kv() {
  jq -Rn --rawfile v "$1" '{data: {api_key: ($v | rtrimstr("\n"))}}' |
    vault POST kv/data/orders-api/config --data @- | jq -r .data.version
}
k8s_value() {
  kubectl -n orders get secret orders-api-config -o jsonpath='{.data.api-key}' 2> /dev/null | base64 -d 2> /dev/null || true
}
synced() { [ "$(k8s_value)" = "$(cat "$1")" ]; }

(umask 077 && openssl rand -hex 16 > "$PRIVATE_DIR/kv-v1" && openssl rand -hex 16 > "$PRIVATE_DIR/kv-v2")
mask "$(cat "$PRIVATE_DIR/kv-v1")"
mask "$(cat "$PRIVATE_DIR/kv-v2")"

log "Writing version 1 to Vault and creating the SecretStore + ExternalSecret"
v="$(write_kv "$PRIVATE_DIR/kv-v1")"
echo "    kv version $v"
start="$(now)"
kubectl apply -f "$ROOT/deploy/eso/secretstore.yaml"
kubectl -n orders wait --for=condition=Ready secretstore/vault --timeout=120s
wait_for 120 "initial sync" synced "$PRIVATE_DIR/kv-v1"
initial="$(since "$start")"

log "Rotating the value in Vault"
v="$(write_kv "$PRIVATE_DIR/kv-v2")"
echo "    kv version $v"
start="$(now)"
wait_for 60 "rotated value to reach the Kubernetes Secret" synced "$PRIVATE_DIR/kv-v2"
propagation="$(since "$start")"
kubectl -n orders get externalsecret orders-api-config \
  -o jsonpath='{range .status.conditions[*]}    {.type}={.status} ({.reason}){"\n"}{end}'
owner="$(kubectl -n orders get secret orders-api-config -o jsonpath='{.metadata.ownerReferences[0].kind}')"
[ "$owner" = ExternalSecret ] || fail "Secret is not owned by the ExternalSecret"

record eso_initial_sync_seconds "$initial"
record eso_rotation_propagation_seconds "$propagation"
record eso_kv_version "$v"
record_str eso_refresh_interval "$(kubectl -n orders get externalsecret orders-api-config -o jsonpath='{.spec.refreshInterval}')"
