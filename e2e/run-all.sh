#!/usr/bin/env bash
# Runs the whole scenario against the current kubectl context, in CI order.
# Expects the image orders-api:ci to be loaded into the cluster.
set -euo pipefail
dir="$(dirname "$0")"
trap '"$dir/cleanup.sh"; "$dir/summary.sh"' EXIT
for step in setup vault-init configure deploy-app test-dynamic-db test-pki test-transit \
  test-eso attacks test-audit test-failover; do
  "$dir/$step.sh"
done
