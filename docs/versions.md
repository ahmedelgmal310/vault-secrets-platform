# Pinned versions

Every tool, chart, image and action is pinned. Images use `tag@sha256:digest`, actions
use a full commit SHA with the version in a comment, Go modules are locked by `go.sum`
and the Terraform provider by `terraform/.terraform.lock.hcl`. The rule is that a
version is adopted only after it has been public for **at least 14 days**; Dependabot
enforces the same cooldown (`.github/dependabot.yml`). Versions were checked on
2026-10-28.

Where each pin lives: chart and runtime image versions in `e2e/lib.sh`, build images in
`Dockerfile`, CI tools and actions in `.github/workflows/ci.yml`, Go modules in
`go.mod`, the provider in `terraform/versions.tf`. Update this file in the same change.

## Exception: Go 1.27.3

Go 1.27.3 was released on 2026-10-19 (9 days before the check) with security fixes to
`crypto/x509`. The previous release, 1.27.2 (2026-10-08), passes the cooldown, but
govulncheck reports the `crypto/x509` vulnerability as reachable from this code (TLS
certificate parsing and verification). Running a toolchain with a known, reachable
vulnerability is worse than skipping the cooldown for a security patch from the Go
team, so CI and the Dockerfile use 1.27.3. This is the only exception.

## Platform (`e2e/lib.sh`, `deploy/`)

| Component | Version | Released | Pin |
|---|---|---|---|
| HashiCorp Vault | 2.1.2 | 2026-10-07 | `hashicorp/vault@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55` |
| Vault Helm chart | 0.34.1 | 2026-08-13 | chart version |
| External Secrets Operator chart (app v2.12.0) | 2.12.0 | 2026-10-06 | chart version (chart has no digest field; image is `ghcr.io/external-secrets/external-secrets:v2.12.0`) |
| PostgreSQL | 18.6 (alpine3.24) | 2026-08-13 | `postgres@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5` |
| kind | v0.33.0 | 2026-08-26 | `helm/kind-action` input |
| Kubernetes (kind node) | v1.36.4 | 2026-08-20 | `kindest/node@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed` |
| kubectl | v1.36.4 | 2026-08-20 | `helm/kind-action` input |
| Helm | v4.3.0 | 2026-09-09 | `azure/setup-helm` input |

Official images are rebuilt in place for OS patches, so the digest is the one the tag
pointed to on the check date; the PostgreSQL release itself is from August.

## Configuration as code (`terraform/`)

| Component | Version | Released |
|---|---|---|
| Terraform | 1.16.5 | 2026-10-02 |
| hashicorp/vault provider | 5.12.0 | 2026-09-17 |
| tflint | v0.64.0 (SHA-256 verified) | 2026-07-17 |

## Service (`Dockerfile`, `go.mod`)

| Component | Version | Pin |
|---|---|---|
| golang (build stage) | 1.27.3-alpine3.24 | `sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb` |
| distroless static-debian13:nonroot (runtime) | | `sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99` |
| github.com/jackc/pgx/v5 | v5.11.0 (2026-09-07) | `go.sum` |
| golang.org/x/text | v0.43.0 (2026-10-09) | `go.sum` |
| golang.org/x/sync | v0.24.0 (2026-09-23) | `go.sum` |

The Vault client is a small in-repo package (`internal/vault`) rather than the official
SDK, which keeps the dependency tree to pgx and two `x/` modules.

## CI (`.github/workflows/ci.yml`)

| Tool | Version | Released | Pin |
|---|---|---|---|
| actions/checkout | v7.0.1 | 2026-07-20 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/setup-go | v7.0.0 | 2026-07-16 | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` |
| actions/upload-artifact | v7.0.2 | 2026-10-07 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| golangci/golangci-lint-action | v9.3.0 (golangci-lint v2.14.0, 2026-09-24) | 2026-06-29 | `ba0d7d2ec06a0ea1cb5fa41b2e4a3ab91d21278a` |
| hashicorp/setup-terraform | v4.0.1 | 2026-05-12 | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` |
| helm/kind-action | v1.15.1 | 2026-10-06 | `1544676c07bb3570fcb70166beaa07c4528fd4aa` |
| azure/setup-helm | v5.0.1 | 2026-06-23 | `9bc31f4ebc9c6b171d7bfbaa5d006ae7abdb4310` |
| docker/setup-buildx-action | v4.4.1 | 2026-09-16 | `f87e5991a6d7451dcb8d9637bfbc97413f497069` |
| docker/build-push-action | v7.4.0 | 2026-09-15 | `c3c9e263c25d99ce0380d002d59b67737d91b0dc` |
| govulncheck | v1.9.0 | 2026-10-11 | module version |
| Gitleaks | v8.30.1 | 2026-03-21 | `sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` |
| actionlint | 1.7.12 | 2026-03-30 | `sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667` |
| hadolint | v2.15.1 | 2026-07-31 | `sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d` |
| Trivy | 0.75.0 | 2026-10-01 | `sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa` |
| kubeconform | v0.8.0 | 2026-06-04 | SHA-256 `9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883` |
| CRDs-catalog (schemas for kubeconform) | commit | 2026-10-08 | `63669a570e231d4f1f8396d229a1de512bcf0a34` |
| shellcheck | preinstalled on the runner image | | |
