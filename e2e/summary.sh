#!/usr/bin/env bash
# Renders e2e-results/results.json as a Markdown table (job summary + file).
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"

v() { jq -r --arg k "$1" '.[$k] // "n/a" | tostring' "$RESULTS"; }

{
  echo "## vault-secrets-platform e2e results"
  echo
  echo "Vault $(v vault_version), PostgreSQL $(v postgres_version), run ${GITHUB_RUN_ID:-local}"
  echo
  echo "| Check | Result |"
  echo "|---|---|"
  echo "| Vault cluster | $(v raft_voters) Raft voters, init + unseal in $(v vault_init_unseal_seconds) s ($(v vault_key_shares) key shares, threshold 3) |"
  echo "| Terraform | $(v terraform_resources) resources in $(v terraform_apply_seconds) s, re-plan exit code $(v terraform_second_plan_changes) (0 = no drift) |"
  echo "| DB root credential rotated (bootstrap password rejected) | $(v root_credential_rotated) |"
  echo "| orders-api ready (login + cert + DB credential) | $(v app_ready_seconds) s, $(v app_kubernetes_secret_refs) Kubernetes Secret references |"
  echo "| Dynamic DB credential lease | $(v db_lease_ttl_seconds) s; role dropped $(v db_role_dropped_after_seconds) s after issue |"
  echo "| Login with the expired credential | \`$(v db_expired_login_error)\` |"
  echo "| Lease revoke → live session terminated | $(v db_revoke_session_killed_seconds) s |"
  echo "| orders-api rotation at max_ttl | after $(v db_service_rotation_after_seconds) s and $(v db_service_renewals_before_rotation) renewals; old user dropped |"
  echo "| TLS certificate lifetime | $(v tls_cert_lifetime_seconds) s, chain of $(v tls_chain_length), wrong hostname rejected: $(v tls_wrong_hostname_rejected) |"
  echo "| TLS rotation in memory | $(v tls_rotations_observed) rotation(s), ≥ $(v tls_rotation_validity_left_seconds) s of validity left |"
  echo "| Transit | stored as \`$(v transit_ciphertext_prefix)…\`, plaintext rows in DB: $(v transit_plaintext_rows_in_db) |"
  echo "| ESO initial sync / rotation propagation | $(v eso_initial_sync_seconds) s / $(v eso_rotation_propagation_seconds) s (refresh $(v eso_refresh_interval)) |"
  echo "| Access probes | $(v attack_checks_passed)/$(v attack_checks_total) as expected ($(v attack_allowed_as_expected) allowed, $(v attack_denied_as_expected) denied) |"
  echo "| Login denials | $(v attack_login_denials) |"
  echo "| Audit log | $(v audit_entries) entries: $(v audit_service_logins) service logins, $(v audit_denied_logins) denied logins, $(v audit_db_credential_reads) DB credential reads, $(v audit_lease_renewals) renewals, $(v audit_eso_kv_reads) ESO reads, $(v audit_permission_denied) permission denied, $(v audit_plaintext_secret_leaks) plaintext leaks |"
  echo "| Leader failover | new active in $(v vault_failover_seconds) s, node back in $(v vault_node_rejoined_seconds) s, $(v raft_voters_after_failover) voters, service OK: $(v service_ok_after_failover) |"
  echo "| Root token revoked at end of job | $(v root_token_revoked) |"
} > "$RESULTS_DIR/summary.md"

cat "$RESULTS_DIR/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then cat "$RESULTS_DIR/summary.md" >> "$GITHUB_STEP_SUMMARY"; fi
