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

# ─────────────────────────────────────────────────────────────
# Redis server certificate (pki-internal/server)
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/redis.tpl"
  destination = "/certs/redis/.rendered"
}

# ─────────────────────────────────────────────────────────────
# LDAP server certificate (pki-internal/server)
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/ldap.tpl"
  destination = "/certs/ldap/.rendered"
}

# ─────────────────────────────────────────────────────────────
# Loki proxy server certificate (pki-internal/server)
#   Issued for the loki-proxy (nginx) that terminates TLS in front
#   of the plain-HTTP Loki backend. CN = loki.akashic.local.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/loki.tpl"
  destination = "/certs/loki-proxy/.rendered"
}

# ─────────────────────────────────────────────────────────────
# Akashic control server certificate (pki-internal/server)
#   Used for the public TLS listener on the control plane. CN =
#   ctrl.akashic.local. Separate from the mTLS-trust cert below.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-ctrl.tpl"
  destination = "/certs/akashic/.ctrl-rendered"
}

# ─────────────────────────────────────────────────────────────
# Akashic auth server certificate (pki-internal/server)
#   Used for the OAuth/OIDC TLS listener. CN = auth.akashic.local.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-auth.tpl"
  destination = "/certs/akashic/.auth-rendered"
}

# ─────────────────────────────────────────────────────────────
# Akashic control server mTLS cert (pki-mtls-akashic-ctrl/server)
#   Issued from the private mTLS CA so that only CLI + BFF clients
#   signed by the same CA can reach /auth/* control endpoints.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-mtls-ctrl.tpl"
  destination = "/certs/akashic/.mtls-ctrl-rendered"
}

# ─────────────────────────────────────────────────────────────
# Akashic CLI mTLS client cert (pki-mtls-akashic-ctrl/client)
#   Used by akashic-cli to authenticate against the control plane.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-cli-client.tpl"
  destination = "/certs/akashic-cli/.rendered"
}

# ─────────────────────────────────────────────────────────────
# BFF mTLS client cert (pki-mtls-akashic-ctrl/client)
#   Used by the BFF (Backend-For-Frontend) to authenticate against
#   the control plane on behalf of admin web sessions.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/bff-client.tpl"
  destination = "/certs/bff/.rendered"
}
