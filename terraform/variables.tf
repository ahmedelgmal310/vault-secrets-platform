variable "db_admin_password" {
  description = "Initial password of the vault_admin PostgreSQL role. Vault rotates it right after the first apply, so this value stops being valid."
  type        = string
  sensitive   = true
}

variable "postgres_host" {
  description = "PostgreSQL host as seen from the Vault pods."
  type        = string
  default     = "postgres.db.svc"
}

variable "app_namespace" {
  description = "Namespace of orders-api and its ExternalSecret."
  type        = string
  default     = "orders"
}

variable "db_default_ttl" {
  description = "Default lease TTL (seconds) of dynamic database credentials."
  type        = number
  default     = 20
}

variable "db_max_ttl" {
  description = "Maximum lease TTL (seconds) of dynamic database credentials, including renewals."
  type        = number
  default     = 60

  validation {
    condition     = var.db_max_ttl >= var.db_default_ttl
    error_message = "db_max_ttl must be greater than or equal to db_default_ttl."
  }
}

variable "cert_max_ttl" {
  description = "Maximum TTL (seconds) of orders-api TLS certificates."
  type        = number
  default     = 300
}
