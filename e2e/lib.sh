#!/usr/bin/env bash
# Shared helpers for the e2e scripts. Source it; do not execute it.
#
# Secret handling rules for every script:
#   - Unseal keys and the root token live only in $VAULT_INIT_FILE on the
#     runner (mode 600, outside the workspace) and are masked in CI logs.
#   - Secrets are passed to tools on stdin or in files, never as arguments.
#   - Nothing secret is written to $RESULTS_DIR, which is uploaded.
set -euo pipefail

# --- pinned versions (also listed in docs/versions.md) ----------------------
VAULT_CHART_VERSION="0.34.1"
VAULT_IMAGE_TAG="2.1.2@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55"
ESO_CHART_VERSION="2.12.0"
POSTGRES_IMAGE="postgres:18.6-alpine3.24@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5"
export VAULT_CHART_VERSION VAULT_IMAGE_TAG ESO_CHART_VERSION POSTGRES_IMAGE

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$ROOT/e2e-results}"
RESULTS="$RESULTS_DIR/results.json"
PRIVATE_DIR="${PRIVATE_DIR:-${RUNNER_TEMP:-/tmp}/vsp-private}"
VAULT_INIT_FILE="$PRIVATE_DIR/vault-init.json"
VAULT_HEADER_FILE="$PRIVATE_DIR/vault-token.header"
VAULT_PORT=8200
APP_PORT=8443
APP_HOST="orders-api.orders.svc"
export VAULT_ADDR="http://127.0.0.1:${VAULT_PORT}"

mkdir -p "$RESULTS_DIR"
(umask 077 && mkdir -p "$PRIVATE_DIR")
[ -f "$RESULTS" ] || echo '{}' > "$RESULTS"

log() { printf '\n==> %s\n' "$*"; }
fail() {
  echo "::error::$*" >&2
  exit 1
}

# mask VALUE: hide a secret from GitHub Actions logs.
mask() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$1"; fi; }

now() { date +%s.%N; }
# since START: seconds elapsed, one decimal.
since() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

# record KEY JSON_VALUE / record_str KEY STRING: store a result for the README table.
record() {
  local tmp
  tmp="$(mktemp)"
  jq --arg k "$1" --argjson v "$2" '.[$k] = $v' "$RESULTS" > "$tmp" && mv "$tmp" "$RESULTS"
  printf '    result %s = %s\n' "$1" "$2"
}
record_str() { record "$1" "$(jq -Rn --arg v "$2" '$v')"; }

# --- port-forwards ------------------------------------------------------------
PF_PIDS=()
pf_cleanup() {
  local p
  for p in "${PF_PIDS[@]:-}"; do
    if [ -n "$p" ]; then kill "$p" 2> /dev/null || true; fi
  done
  PF_PIDS=()
}
trap pf_cleanup EXIT

# port_forward NAMESPACE TARGET LOCAL REMOTE
port_forward() {
  kubectl -n "$1" port-forward "$2" "$3:$4" >/dev/null 2>&1 &
  PF_PIDS+=("$!")
  local i
  for i in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$3") 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  fail "port-forward to $1/$2 did not come up"
}

# vault_connect: forward the active Vault node to $VAULT_ADDR.
vault_connect() {
  pf_cleanup
  port_forward vault svc/vault-active "$VAULT_PORT" 8200
}

# vault METHOD PATH [curl args...]: authenticated Vault API call with the
# bootstrap token read from a header file (not from the command line).
vault() {
  local method="$1" path="$2"
  shift 2
  curl -sS --fail-with-body -X "$method" -H "@$VAULT_HEADER_FILE" \
    -H 'Content-Type: application/json' "$VAULT_ADDR/v1/$path" "$@"
}

# active_vault_pod: name of the pod currently labelled vault-active=true.
active_vault_pod() {
  kubectl -n vault get pods -l vault-active=true -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

# unseal_via PORT: send the threshold of unseal keys to a forwarded pod.
unseal_via() {
  local port="$1" threshold i
  threshold="$(jq -r '.keys_base64 | length as $n | if $n >= 3 then 3 else $n end' "$VAULT_INIT_FILE")"
  for i in $(seq 0 $((threshold - 1))); do
    jq -c --argjson i "$i" '{key: .keys_base64[$i]}' "$VAULT_INIT_FILE" |
      curl -sS --fail-with-body -X PUT --data @- "http://127.0.0.1:$port/v1/sys/unseal" > /dev/null
  done
  wait_for 90 "node on port $port to unseal" unsealed "$port"
}
unsealed() { [ "$(curl -sS "http://127.0.0.1:$1/v1/sys/seal-status" | jq -r .sealed)" = "false" ]; }

# --- orders-api ---------------------------------------------------------------
CA_FILE="$RESULTS_DIR/root-ca.pem"

app_connect() { port_forward orders svc/orders-api "$APP_PORT" 8443; }

# app METHOD PATH [curl args...]: call orders-api over verified TLS.
app() {
  local method="$1" path="$2"
  shift 2
  curl -sS --fail-with-body --cacert "$CA_FILE" --resolve "$APP_HOST:$APP_PORT:127.0.0.1" \
    -X "$method" "https://$APP_HOST:$APP_PORT$path" "$@"
}

# --- PostgreSQL -----------------------------------------------------------------
# pg_super SQL: query as the superuser over the pod's Unix socket.
pg_super() { kubectl -n db exec postgres-0 -- psql -U postgres -d app -tAqc "$1"; }

# pg_login USER: password on stdin; prints current_user or the error; returns
# psql's status. TCP to 127.0.0.1 so password authentication applies.
pg_login() {
  # shellcheck disable=SC2016 # expanded by the shell inside the pod
  kubectl -n db exec -i postgres-0 -- sh -c \
    'PGPASSWORD="$(cat)" PGCONNECT_TIMEOUT=5 psql -h 127.0.0.1 -U "$1" -d app -tAqc "select current_user" 2>&1' _ "$1"
}

# poll TIMEOUT_S COMMAND...: run COMMAND once a second until it succeeds;
# returns 1 on timeout.
poll() {
  local timeout="$1" start
  shift
  start="$(date +%s)"
  until "$@"; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then return 1; fi
    sleep 1
  done
}

# wait_for TIMEOUT_S DESCRIPTION COMMAND...: poll, and fail the step on timeout.
wait_for() {
  local timeout="$1" what="$2"
  shift 2
  poll "$timeout" "$@" || fail "timed out after ${timeout}s waiting for: $what"
}
