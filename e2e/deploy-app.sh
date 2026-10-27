#!/usr/bin/env bash
# Deploys orders-api and waits until it has logged in to Vault, obtained a
# TLS certificate and a dynamic database credential (its readiness gate).
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

log "Deploying orders-api"
start="$(now)"
kubectl apply -f "$ROOT/deploy/app/orders-api.yaml"
if ! kubectl -n orders rollout status deployment/orders-api --timeout=180s; then
  kubectl -n orders logs deployment/orders-api --tail=50 || true
  fail "orders-api did not become ready"
fi
record app_ready_seconds "$(since "$start")"

log "orders-api pod has no Secret volumes and no secret env vars"
pod="$(kubectl -n orders get pod -l app.kubernetes.io/name=orders-api -o jsonpath='{.items[0].metadata.name}')"
secret_refs="$(kubectl -n orders get pod "$pod" -o json |
  jq '[.spec.volumes[]? | select(.secret)] + [.spec.containers[].env[]? | select(.valueFrom.secretKeyRef)] | length')"
[ "$secret_refs" = 0 ] || fail "orders-api pod references Kubernetes Secrets"
record app_kubernetes_secret_refs "$secret_refs"

log "Fetching the PKI root CA (public) for TLS verification"
vault_connect
curl -sS --fail-with-body "$VAULT_ADDR/v1/pki/ca/pem" > "$CA_FILE"
openssl x509 -in "$CA_FILE" -noout -subject
