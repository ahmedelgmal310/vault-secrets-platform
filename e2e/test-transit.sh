#!/usr/bin/env bash
# Proves transit encryption as a service: the note stored in PostgreSQL is
# Vault ciphertext, the plaintext appears nowhere in the table, and the row
# was written by the current dynamic database user.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

app_connect
note="note-$(openssl rand -hex 8)"
echo "$note" > "$PRIVATE_DIR/transit-note"

log "POST /v1/orders"
resp="$(jq -n --arg n "$note" '{item: "book", note: $n}' | app POST /v1/orders -H 'Content-Type: application/json' --data @-)"
id="$(echo "$resp" | jq -r .id)"
ct="$(echo "$resp" | jq -r .note_ciphertext)"
echo "    order $id, ciphertext ${ct:0:24}..."
[[ "$ct" == vault:v1:* ]] || fail "note is not Vault transit ciphertext: $ct"

stored="$(pg_super "select note_ciphertext from orders where id = $id")"
[ "$stored" = "$ct" ] || fail "database holds something other than the ciphertext"
leaks="$(pg_super "select count(*) from orders where note_ciphertext like '%$note%' or item like '%$note%'")"
[ "$leaks" = 0 ] || fail "plaintext found in the orders table"
created_by="$(pg_super "select created_by from orders where id = $id")"
current="$(app GET /status | jq -r .database.username)"
[ "$created_by" = "$current" ] || fail "row written by '$created_by', service uses '$current'"

log "GET /v1/orders/$id decrypts through Vault"
back="$(app GET "/v1/orders/$id" | jq -r .note)"
[ "$back" = "$note" ] || fail "decrypted note does not match"

record_str transit_ciphertext_prefix "${ct:0:9}"
record transit_plaintext_rows_in_db "$leaks"
record_str transit_row_written_by "$created_by"
