#!/usr/bin/env bash
# Runs the access probes in deploy/attacks/probes.yaml: the legitimate
# identity is held to its policy, and wrong service accounts, a wrong
# namespace and a wrong token audience are all refused.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

out="$RESULTS_DIR/attacks"
mkdir -p "$out"
jobs=(
  "orders probe-least-privilege"
  "orders probe-wrong-sa"
  "orders probe-wrong-sa-eso-role"
  "rogue probe-wrong-namespace"
  "orders probe-wrong-audience"
)

log "Launching probe Jobs"
for j in "${jobs[@]}"; do
  read -r ns name <<< "$j"
  kubectl -n "$ns" delete job "$name" --ignore-not-found --wait=true > /dev/null
done
kubectl apply -f "$ROOT/deploy/attacks/probes.yaml"

finished() {
  local s f
  s="$(kubectl -n "$1" get job "$2" -o jsonpath='{.status.succeeded}')"
  f="$(kubectl -n "$1" get job "$2" -o jsonpath='{.status.failed}')"
  [ "${s:-0}" -ge 1 ] || [ "${f:-0}" -ge 1 ]
}

failed_jobs=0
for j in "${jobs[@]}"; do
  read -r ns name <<< "$j"
  wait_for 180 "job $ns/$name" finished "$ns" "$name"
  kubectl -n "$ns" logs "job/$name" > "$out/$name.jsonl"
  if [ "$(kubectl -n "$ns" get job "$name" -o jsonpath='{.status.succeeded}')" != 1 ]; then
    echo "::error::probe $name had unexpected outcomes"
    failed_jobs=$((failed_jobs + 1))
  fi
done

log "Probe results"
jq -rs '.[] | select(.summary | not) |
  "    \(if .pass then "PASS" else "FAIL" end)  [\(.scenario)] \(.check)  expect=\(.expect) got=\(if .allowed then "allowed" else "denied" end)\(if .status then " (HTTP \(.status))" else "" end)"' \
  "$out"/*.jsonl

total="$(jq -s '[.[] | select(.summary | not)] | length' "$out"/*.jsonl)"
passed="$(jq -s '[.[] | select((.summary | not) and .pass)] | length' "$out"/*.jsonl)"
denied="$(jq -s '[.[] | select((.summary | not) and .expect == "deny" and (.allowed | not))] | length' "$out"/*.jsonl)"
allowed="$(jq -s '[.[] | select((.summary | not) and .expect == "allow" and .allowed)] | length' "$out"/*.jsonl)"
login_errors="$(jq -rs '[.[] | select((.summary | not) and (.check | startswith("login")) and (.allowed | not)) | "\(.scenario): \(.error | sub("^vault: [A-Z]+ [^:]+: "; ""))"] | join(" | ")' "$out"/*.jsonl)"
echo "    $passed/$total checks matched expectations ($allowed allowed as intended, $denied denied as intended)"
echo "    login denials: $login_errors"

record attack_checks_total "$total"
record attack_checks_passed "$passed"
record attack_denied_as_expected "$denied"
record attack_allowed_as_expected "$allowed"
record_str attack_login_denials "$login_errors"
if [ "$failed_jobs" != 0 ] || [ "$passed" != "$total" ]; then
  fail "$((total - passed)) probe checks did not match expectations"
fi
