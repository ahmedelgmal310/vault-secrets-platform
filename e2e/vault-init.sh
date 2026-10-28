#!/usr/bin/env bash
# Initialises vault-0 (5 key shares, threshold 3), unseals it, joins vault-1
# and vault-2 to the Raft cluster and unseals them. The init response (unseal
# keys + root token) is written only to $VAULT_INIT_FILE on the runner.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

pod_running() { [ "$(kubectl -n vault get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ]; }
api_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$1/v1/sys/seal-status")" = 200 ]; }
is_leader() { [ "$(curl -s "http://127.0.0.1:$1/v1/sys/leader" | jq -r .is_self)" = true ]; }
voters() {
  vault GET sys/storage/raft/autopilot/state |
    jq -r '[.data.servers[] | select((.status == "leader" or .status == "voter") and .healthy == true)] | length'
}
three_voters() { [ "$(voters 2>/dev/null)" = 3 ]; }

log "Waiting for Vault pods to run (they stay unready until unsealed)"
for i in 0 1 2; do
  wait_for 300 "pod vault-$i Running" pod_running "vault-$i"
done

start="$(now)"
port_forward vault pod/vault-0 8210 8200
wait_for 60 "vault-0 API" api_up 8210

if [ "$(curl -sS http://127.0.0.1:8210/v1/sys/seal-status | jq -r .initialized)" = "true" ]; then
  [ -s "$VAULT_INIT_FILE" ] || fail "Vault is already initialised but $VAULT_INIT_FILE is missing"
  log "Vault already initialised; reusing $VAULT_INIT_FILE"
else
  log "operator init (5 shares, threshold 3)"
  (
    umask 077
    curl -sS --fail-with-body -X PUT --data '{"secret_shares":5,"secret_threshold":3}' \
      http://127.0.0.1:8210/v1/sys/init > "$VAULT_INIT_FILE"
  )
fi
mask "$(jq -r .root_token "$VAULT_INIT_FILE")"
while read -r k; do mask "$k"; done < <(jq -r '.keys_base64[], .keys[]' "$VAULT_INIT_FILE")
(
  umask 077
  printf 'X-Vault-Token: %s\n' "$(jq -r .root_token "$VAULT_INIT_FILE")" > "$VAULT_HEADER_FILE"
)

log "Unsealing vault-0"
unseal_via 8210
wait_for 60 "vault-0 to become leader" is_leader 8210

port=8211
for pod in vault-1 vault-2; do
  log "Joining $pod to the Raft cluster and unsealing it"
  port_forward vault "pod/$pod" "$port" 8200
  wait_for 60 "$pod API" api_up "$port"
  if [ "$(curl -sS "http://127.0.0.1:$port/v1/sys/seal-status" | jq -r .initialized)" != "true" ]; then
    curl -sS --fail-with-body -X PUT --data '{"leader_api_addr":"http://vault-0.vault-internal:8200"}' \
      "http://127.0.0.1:$port/v1/sys/storage/raft/join" | jq -c .
  fi
  unseal_via "$port"
  port=$((port + 1))
done

log "Waiting for 3 healthy Raft voters"
has_active() { [ -n "$(active_vault_pod)" ]; }
wait_for 60 "a pod labelled vault-active" has_active
vault_connect
if ! poll 120 three_voters; then
  vault GET sys/storage/raft/autopilot/state | jq . || true
  kubectl -n vault get pods --show-labels || true
  fail "Raft cluster did not reach 3 healthy voters"
fi
vault GET sys/storage/raft/autopilot/state | jq -r '.data.servers[] | "    \(.id)  \(.status)  healthy=\(.healthy)"'

record vault_init_unseal_seconds "$(since "$start")"
record raft_voters "$(voters)"
record_str vault_version "$(curl -sS "$VAULT_ADDR/v1/sys/seal-status" | jq -r .version)"
record vault_key_shares "$(jq '.keys_base64 | length' "$VAULT_INIT_FILE")"
