#!/usr/bin/env bash
# Proves the audit device recorded what happened: the service's logins and
# credential reads, ESO's KV reads, every denied attempt from the probes, and
# that no secret value appears in the log in plaintext.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

pod="$(active_vault_pod)"
[ -n "$pod" ] || fail "no active Vault pod"
log "Copying the audit log from $pod (kept on the runner; only a redacted excerpt is uploaded)"
log_file="$PRIVATE_DIR/audit.log"
kubectl -n vault exec "$pod" -- cat /vault/audit/audit.log > "$log_file"

count() { jq -s "[.[] | select($1)] | length" "$log_file"; }
entries="$(wc -l < "$log_file" | tr -d ' ')"
resp='.type == "response"'
logins_ok="$(count "$resp and .request.path == \"auth/kubernetes/login\" and (.error // \"\") == \"\" and (.auth.metadata.service_account_name // \"\") == \"orders-api\"")"
logins_denied="$(count "$resp and .request.path == \"auth/kubernetes/login\" and (.error // \"\") != \"\"")"
db_reads="$(count "$resp and .request.path == \"database/creds/orders-api\" and (.auth.metadata.service_account_name // \"\") == \"orders-api\" and (.error // \"\") == \"\"")"
renewals="$(count "$resp and .request.path == \"sys/leases/renew\" and (.auth.metadata.service_account_name // \"\") == \"orders-api\"")"
revokes="$(count "$resp and (.request.path | startswith(\"sys/leases/revoke/database/creds/orders-api/\")) and (.auth.metadata.service_account_name // \"\") == \"orders-api\"")"
pki_issues="$(count "$resp and .request.path == \"pki_int/issue/orders-api\" and (.error // \"\") == \"\"")"
eso_reads="$(count "$resp and .request.path == \"kv/data/orders-api/config\" and (.auth.metadata.service_account_name // \"\") == \"orders-eso\"")"
denied="$(count "$resp and .error == \"permission denied\"")"

echo "    entries:                         $entries"
echo "    orders-api logins:               $logins_ok"
echo "    denied logins:                   $logins_denied"
echo "    orders-api DB credential reads:  $db_reads"
echo "    orders-api lease renewals:       $renewals"
echo "    orders-api lease revocations:    $revokes"
echo "    TLS certificates issued:         $pki_issues"
echo "    ESO KV reads:                    $eso_reads"
echo "    permission denied responses:     $denied"
echo "    denied paths:"
jq -rs '[.[] | select(.type == "response" and .error == "permission denied") | .request.path] | unique | .[] | "      " + .' "$log_file"
echo "    denied login reasons:"
jq -rs '[.[] | select(.type == "response" and .request.path == "auth/kubernetes/login" and (.error // "") != "") | .error] | unique | .[] | "      " + .' "$log_file"

for n in "$logins_ok" "$logins_denied" "$db_reads" "$renewals" "$pki_issues" "$eso_reads" "$denied"; do
  [ "$n" -gt 0 ] || fail "an expected class of audit events is missing"
done

log "No secret value appears in plaintext"
leaks=0
for f in kv-v1 kv-v2 transit-note; do
  if [ -s "$PRIVATE_DIR/$f" ] && grep -qF "$(cat "$PRIVATE_DIR/$f")" "$log_file"; then
    echo "::error::$f found in the audit log in plaintext"
    leaks=$((leaks + 1))
  fi
done
[ "$leaks" = 0 ] || fail "secret values leaked into the audit log"
hmac="$(jq -rs '[.[] | select(.type == "response" and .request.path == "database/creds/orders-api" and .response.data.password != null) | .response.data.password] | .[0]' "$log_file")"
[[ "$hmac" == hmac-sha256:* ]] || fail "database password in the audit log is not HMAC-ed"

# Redacted excerpt for the artifact: who, what, outcome. No request/response bodies.
jq -c 'select(.type == "response") | {time, path: .request.path, op: .request.operation,
  identity: (.auth.metadata.service_account_namespace // "") + "/" + (.auth.metadata.service_account_name // .auth.display_name // ""),
  error: (.error // "")}' "$log_file" | grep -v '"path":"sys/storage/raft' > "$RESULTS_DIR/audit-excerpt.jsonl" || true

record audit_entries "$entries"
record audit_service_logins "$logins_ok"
record audit_denied_logins "$logins_denied"
record audit_db_credential_reads "$db_reads"
record audit_lease_renewals "$renewals"
record audit_lease_revocations "$revokes"
record audit_pki_issues "$pki_issues"
record audit_eso_kv_reads "$eso_reads"
record audit_permission_denied "$denied"
record audit_plaintext_secret_leaks "$leaks"
