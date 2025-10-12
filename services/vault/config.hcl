# UI (https://localhost:8200/ui)
ui = true

# Storage backend
storage "file" {
  path = "/vault/file"
}

# API address
api_addr      = "https://0.0.0.0:8200"
cluster_addr  = "https://0.0.0.0:8201"

# API listener
listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = false
  tls_cert_file   = "/vault/certs/vault/vault.crt"
  tls_key_file    = "/vault/certs/vault/vault.key"
}

# Disable mlock in development (Docker containers)
# For production on Linux, ensure the container has IPC_LOCK capability
disable_mlock = false

# Log level
log_level = "info"

# Telemetry (optional - for monitoring)
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = false
}

# Plugin directory
plugin_directory = "/vault/plugins"

# Default lease and token TTLs
default_lease_ttl = "768h"  # 32 days
max_lease_ttl = "8760h"     # 1 year
