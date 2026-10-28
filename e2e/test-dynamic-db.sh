#!/usr/bin/env bash
# Proves the database secrets engine end to end:
#   A. a dynamic credential works, then stops working when its lease expires
#   B. revoking a lease kills live sessions and blocks new logins at once
#   C. orders-api renews its lease, rotates to a new user at max_ttl and the
#      old user is gone from PostgreSQL
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

vault_connect
role_count() { pg_super "select count(*) from pg_roles where rolname = '$1'"; }
role_gone() { [ "$(role_count "$1")" = 0 ]; }
sessions() { pg_super "select count(*) from pg_stat_activity where usename = '$1'"; }

# issue_cred FILE: read database/creds/orders-api into a private file.
issue_cred() {
  (umask 077 && vault GET database/creds/orders-api > "$1")
  mask "$(jq -r .data.password "$1")"
}

log "A. Dynamic credential: works while the lease is valid, fails after expiry"
cred="$PRIVATE_DIR/cred-a.json"
issue_cred "$cred"
issued="$(now)"
user="$(jq -r .data.username "$cred")"
ttl="$(jq -r .lease_duration "$cred")"
echo "    issued $user, lease ${ttl}s"
got="$(jq -r .data.password "$cred" | pg_login "$user")" || fail "fresh credential rejected: $got"
[ "$got" = "$user" ] || fail "logged in as '$got', expected $user"
[ "$(role_count "$user")" = 1 ] || fail "role $user does not exist"
wait_for $((ttl + 30)) "Vault to revoke $user at lease expiry" role_gone "$user"
dropped_after="$(since "$issued")"
if err="$(jq -r .data.password "$cred" | pg_login "$user")"; then
  fail "expired credential still works"
fi
echo "    after expiry: $err"
record db_lease_ttl_seconds "$ttl"
record db_role_dropped_after_seconds "$dropped_after"
record_str db_expired_login_error "$(echo "$err" | grep -o 'FATAL:.*' | head -1)"

log "B. Revocation terminates live sessions and blocks new logins"
cred="$PRIVATE_DIR/cred-b.json"
issue_cred "$cred"
user="$(jq -r .data.username "$cred")"
lease="$(jq -r .lease_id "$cred")"
# A long-running session held open with the credential.
# shellcheck disable=SC2016 # expanded by the shell inside the pod
jq -r .data.password "$cred" | kubectl -n db exec -i postgres-0 -- sh -c \
  'PGPASSWORD="$(cat)" psql -h 127.0.0.1 -U "$1" -d app -tAqc "select pg_sleep(120)"' _ "$user" > /dev/null 2>&1 &
holder=$!
has_session() { [ "$(sessions "$user")" -ge 1 ]; }
wait_for 30 "a live session for $user" has_session
revoked_at="$(now)"
vault PUT "sys/leases/revoke/$lease" -o /dev/null
no_session() { [ "$(sessions "$user")" = 0 ]; }
wait_for 15 "sessions of $user to be terminated" no_session
killed_after="$(since "$revoked_at")"
if wait "$holder"; then fail "the held session finished normally instead of being terminated"; fi
if jq -r .data.password "$cred" | pg_login "$user" > /dev/null; then fail "revoked credential still works"; fi
role_gone "$user" || fail "role $user still exists after revocation"
record db_revoke_session_killed_seconds "$killed_after"
rm -f "$PRIVATE_DIR"/cred-*.json

log "C. orders-api renews, then rotates at max_ttl and drops the old user"
app_connect
status() { app GET /status; }
st="$(status)"
u1="$(echo "$st" | jq -r .database.username)"
r0="$(echo "$st" | jq -r .database.rotations)"
issued1="$(echo "$st" | jq -r .database.issued_at)"
whoami="$(app GET /v1/db/whoami | jq -r .current_user)"
[ "$whoami" = "$u1" ] || fail "service queries as '$whoami' but reports '$u1'"
echo "    current user $u1 (rotations so far: $r0)"
rotated() { [ "$(status | jq -r .database.rotations)" -gt "$r0" ]; }
wait_for 150 "orders-api to rotate its database credential" rotated
st="$(status)"
u2="$(echo "$st" | jq -r .database.username)"
issued2="$(echo "$st" | jq -r .database.issued_at)"
renewals="$(echo "$st" | jq -r .database.renewals)"
[ "$u2" != "$u1" ] || fail "rotation kept the same username"
[ "$(echo "$st" | jq -r .database.previous_username)" = "$u1" ] || fail "previous_username mismatch"
whoami="$(app GET /v1/db/whoami | jq -r .current_user)"
[ "$whoami" = "$u2" ] || fail "after rotation the service queries as '$whoami', expected $u2"
wait_for 15 "old user $u1 to be dropped" role_gone "$u1"
[ "$(sessions "$u1")" = 0 ] || fail "sessions of $u1 survived rotation"
lifetime="$(jq -rn --arg a "$issued1" --arg b "$issued2" '(($b | sub("\\.[0-9]+";"") | fromdateiso8601) - ($a | sub("\\.[0-9]+";"") | fromdateiso8601))')"
echo "    rotated $u1 -> $u2 after ${lifetime}s, $renewals lease renewals so far"
record db_service_rotation_after_seconds "$lifetime"
record db_service_renewals_before_rotation "$renewals"
record_str db_service_user_before "$u1"
record_str db_service_user_after "$u2"
