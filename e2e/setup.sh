#!/usr/bin/env bash
# Installs PostgreSQL, Vault (3-node Raft, sealed) and External Secrets
# Operator on the current kind cluster.
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

log "Namespaces"
for ns in vault db orders rogue; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
done

log "PostgreSQL (random bootstrap passwords created per run, never stored in git)"
# The values go straight from openssl into the Secret via files.
(
  umask 077
  # No trailing newline: the value must be identical in the Secret, in the
  # PostgreSQL init script and in Terraform.
  openssl rand -hex 24 | tr -d '\n' > "$PRIVATE_DIR/postgres-password"
  openssl rand -hex 24 | tr -d '\n' > "$PRIVATE_DIR/vault-admin-password"
)
mask "$(cat "$PRIVATE_DIR/postgres-password")"
mask "$(cat "$PRIVATE_DIR/vault-admin-password")"
kubectl -n db create secret generic postgres-bootstrap \
  --from-file=postgres-password="$PRIVATE_DIR/postgres-password" \
  --from-file=vault-admin-password="$PRIVATE_DIR/vault-admin-password" \
  --dry-run=client -o yaml | kubectl apply -f -
sed "s|image: POSTGRES_IMAGE|image: ${POSTGRES_IMAGE}|" "$ROOT/deploy/postgres/postgres.yaml" | kubectl apply -f -

log "Vault ${VAULT_IMAGE_TAG%@*} via chart ${VAULT_CHART_VERSION} (pods start sealed)"
helm repo add hashicorp https://helm.releases.hashicorp.com --force-update > /dev/null
helm repo add external-secrets https://charts.external-secrets.io --force-update > /dev/null
helm repo update > /dev/null
helm upgrade --install vault hashicorp/vault --version "$VAULT_CHART_VERSION" -n vault \
  -f "$ROOT/deploy/vault/values.yaml" --set "server.image.tag=${VAULT_IMAGE_TAG}"

log "External Secrets Operator chart ${ESO_CHART_VERSION}"
helm upgrade --install external-secrets external-secrets/external-secrets --version "$ESO_CHART_VERSION" \
  -n external-secrets --create-namespace -f "$ROOT/deploy/eso/values.yaml" --wait --timeout 5m

log "Waiting for PostgreSQL"
kubectl -n db rollout status statefulset/postgres --timeout=300s
record_str postgres_version "$(pg_super 'show server_version')"
