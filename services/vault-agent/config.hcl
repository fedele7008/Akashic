# ═══════════════════════════════════════════════════════════════
# Akashic Vault Agent
# ═══════════════════════════════════════════════════════════════
# Authenticates via AppRole, then renders certificate templates.
# Each template uses a single pkiCert call with writeToFile to
# produce separate .crt, .key, and ca.pem files atomically.
#
# Certificates are auto-renewed at ~2/3 of their TTL.
# ═══════════════════════════════════════════════════════════════

vault {
  address = "https://vault:8200"
  ca_cert = "/certs/vault/root-ca.crt"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"

    config = {
      role_id_file_path                   = "/vault-agent/auth/vault-agent/role-id"
      secret_id_file_path                 = "/vault-agent/auth/vault-agent/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/vault-agent/token"
    }
  }
}

# ─────────────────────────────────────────────────────────────
# PostgreSQL server certificate (pki-internal/server)
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/postgres.tpl"
  destination = "/certs/postgres/.rendered"
}
