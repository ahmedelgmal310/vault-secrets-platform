#!/usr/bin/env bash
# Deletes the active Vault pod and proves a standby takes over, the deleted
# node rejoins after an unseal, and orders-api keeps working throughout.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

old="$(active_vault_pod)"
[ -n "$old" ] || fail "no active Vault pod"
app_connect
before="$(app GET /status | jq '.database.renewals + .database.rotations')"

log "Deleting the active node $old"
start="$(now)"
kubectl -n vault delete pod "$old" --wait=false
new_leader() {
  local p
  p="$(active_vault_pod)"
  [ -n "$p" ] && [ "$p" != "$old" ]
}
wait_for 60 "a standby to become active" new_leader
failover="$(since "$start")"
echo "    $(active_vault_pod) is active after ${failover}s"

log "Unsealing the restarted $old (Raft data is on its PVC, so it rejoins)"
running() { [ "$(kubectl -n vault get pod "$old" -o jsonpath='{.status.phase}' 2> /dev/null)" = Running ]; }
wait_for 180 "$old to restart" running
port_forward vault "pod/$old" 8215 8200
api_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8215/v1/sys/seal-status)" = 200 ]; }
wait_for 60 "$old API" api_up
unseal_via 8215
rejoin="$(since "$start")"

vault_connect
healthy() { [ "$(vault GET sys/storage/raft/autopilot/state 2> /dev/null | jq -r .data.healthy)" = true ]; }
wait_for 120 "Raft autopilot to report healthy" healthy
voters="$(vault GET sys/storage/raft/autopilot/state | jq '[.data.servers[] | select(.status == "voter" and .healthy)] | length')"

log "orders-api keeps renewing and serving through the failover"
app_connect
progressed() { [ "$(app GET /status | jq '.database.renewals + .database.rotations')" -gt "$before" ]; }
wait_for 90 "a database lease renewal or rotation after failover" progressed
app GET /v1/db/whoami | jq -c .
jq -n '{item: "after-failover", note: "still encrypted"}' | app POST /v1/orders -H 'Content-Type: application/json' --data @- | jq -c '{id}'

record vault_failover_seconds "$failover"
record vault_node_rejoined_seconds "$rejoin"
record raft_voters_after_failover "$voters"
record service_ok_after_failover true
