#!/usr/bin/env bash
# Revokes the bootstrap root token and deletes every private file. Runs even
# when earlier steps failed.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"
set +e

if [ -s "$VAULT_HEADER_FILE" ] && [ -n "$(active_vault_pod)" ]; then
  log "Revoking the root token"
  vault_connect
  vault POST auth/token/revoke-self -o /dev/null
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "@$VAULT_HEADER_FILE" "$VAULT_ADDR/v1/auth/token/lookup-self")"
  echo "    lookup-self with the old root token: HTTP $code"
  if [ "$code" = 403 ]; then record root_token_revoked true; else record root_token_revoked false; fi
fi

log "Removing private files"
rm -rf "$PRIVATE_DIR"
exit 0
