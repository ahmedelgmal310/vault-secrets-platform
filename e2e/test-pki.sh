#!/usr/bin/env bash
# Proves the PKI engine: orders-api serves a short-lived certificate that
# chains to the Vault root, is valid only for its own name, and is replaced
# in memory before it expires (no restart, no file on disk).
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

app_connect
work="$(mktemp -d)"

# served_cert: write the served chain to $work/chain.pem and the leaf to $work/leaf.pem.
served_cert() {
  openssl s_client -connect "127.0.0.1:$APP_PORT" -servername "$APP_HOST" -showcerts < /dev/null 2> /dev/null |
    awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > "$work/chain.pem"
  awk '/BEGIN CERTIFICATE/{n++} n==1' "$work/chain.pem" > "$work/leaf.pem"
  awk '/BEGIN CERTIFICATE/{n++} n>=2' "$work/chain.pem" > "$work/intermediates.pem"
}
serial() { openssl x509 -in "$work/leaf.pem" -noout -serial | cut -d= -f2; }
epoch() { date -d "$(openssl x509 -in "$work/leaf.pem" -noout "-$1" | cut -d= -f2)" +%s; }

log "Served certificate"
served_cert
s1="$(serial)"
nb1="$(epoch startdate)"
na1="$(epoch enddate)"
lifetime=$((na1 - nb1))
chain_len="$(grep -c 'BEGIN CERTIFICATE' "$work/chain.pem")"
openssl x509 -in "$work/leaf.pem" -noout -subject -issuer -ext subjectAltName
echo "    serial $s1, valid ${lifetime}s (includes Vault's 30s not-before backdate), chain of $chain_len"
[ "$lifetime" -le 330 ] || fail "certificate lifetime ${lifetime}s exceeds the role max_ttl"
openssl verify -CAfile "$CA_FILE" -untrusted "$work/intermediates.pem" "$work/leaf.pem" || fail "chain does not verify against the Vault root CA"

log "Hostname verification: the right name passes, another name fails"
app GET /healthz -o /dev/null
if curl -sS --cacert "$CA_FILE" --resolve "evil.example.com:$APP_PORT:127.0.0.1" \
  "https://evil.example.com:$APP_PORT/healthz" -o /dev/null 2> "$work/curl.err"; then
  fail "certificate accepted for a name it was not issued for"
fi
echo "    other name rejected: $(tr -d '\n' < "$work/curl.err" | cut -c1-120)"

log "Waiting for in-memory rotation"
expired_served=0
rotated() {
  served_cert
  [ "$(date +%s)" -lt "$(epoch enddate)" ] || expired_served=1
  [ "$(serial)" != "$s1" ]
}
wait_for $((lifetime + 30)) "a new certificate serial" rotated
detected="$(date +%s)"
s2="$(serial)"
[ "$expired_served" = 0 ] || fail "an expired certificate was served"
openssl verify -CAfile "$CA_FILE" -untrusted "$work/intermediates.pem" "$work/leaf.pem" > /dev/null || fail "rotated chain does not verify"
left=$((na1 - detected))
echo "    rotated $s1 -> $s2 with at least ${left}s of validity left on the old certificate"
rotations="$(app GET /status | jq -r .tls.rotations)"

record tls_cert_lifetime_seconds "$lifetime"
record tls_chain_length "$chain_len"
record tls_rotation_validity_left_seconds "$left"
record tls_rotations_observed "$rotations"
record tls_wrong_hostname_rejected true
rm -rf "$work"
