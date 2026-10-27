terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "= 5.12.0"
    }
  }
}

# Address and token come from VAULT_ADDR and VAULT_TOKEN. In CI the token is
# the bootstrap root token, which lives only on the runner and is revoked at
# the end of the job.
provider "vault" {
  # The provider's child token would expire mid-apply on slow runners and adds
  # nothing for a bootstrap run.
  skip_child_token = true
}
