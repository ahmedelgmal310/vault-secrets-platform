# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/ahmedelgmal310/vault-secrets-platform/security/advisories/new).
Do not open a public issue. You can expect an acknowledgement within 72 hours.

## Scope

This repository is a reference platform that runs on a throwaway kind cluster in CI. It is
not a hosted service. Reports about the code, the Vault policies, the Terraform
configuration, the Kubernetes manifests or the CI workflow are all in scope.

## How secrets are handled here

- **No secret is committed.** Gitleaks scans the full git history on every push.
- **Unseal keys and the root token** are created by `vault operator init` inside the CI
  runner, written to a mode-600 file outside the workspace, masked in the logs, never
  uploaded as an artifact, and the root token is revoked at the end of every run.
- **Database bootstrap passwords** are random per run. Vault rotates the `vault_admin`
  password right after Terraform configures the connection, so afterwards only Vault
  knows it. CI asserts that the bootstrap password is rejected.
- **Application credentials** are dynamic (database), short-lived (TLS) or never leave
  Vault (transit key). The service pod mounts no Kubernetes Secret; CI asserts this.
- **Policies** are least privilege and linted in CI (`cmd/policylint`): no wildcards,
  no `sys/` or `auth/` paths, no `sudo`, unless an exception with a written reason sits
  next to the path.
- **Supply chain:** actions pinned to commit SHAs, images pinned by digest, Trivy gate
  on the service image, govulncheck, Dependabot with a 14-day cooldown.

Known limitations (plain HTTP inside the cluster, single-node kind, root token used for
bootstrap) are listed in the README.
