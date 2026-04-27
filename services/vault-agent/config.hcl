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
# Akashic auth server certificate (pki-internal/server)
#   Used for the OAuth/OIDC TLS listener. CN = auth.akashic.local.
#
# Note: there is intentionally NO `pki-internal`-issued cert for
# the CONTROL plane. The control plane is mTLS-only — its server
# cert is issued from `pki-mtls-akashic-ctrl` (see akashic-mtls-ctrl.tpl
# below). An earlier design considered a public TLS listener on the
# control plane in addition to mTLS, but that path was never taken;
# the mTLS-only design ships unchanged. If the control plane ever
# adds a non-mTLS listener in the future, re-introduce a template
# here using `pki-internal/issue/server`.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-auth.tpl"
  destination = "/certs/akashic/.auth-rendered"
}

# ─────────────────────────────────────────────────────────────
# Akashic API server certificate (pki-internal/server)
#   Phase 8: TLS listener for the bearer-token-authenticated
#   resource server. CN = api.akashic.local. Public-facing (browser
#   reaches via api.<domain> through the proxy), so issued from
#   the same `pki-internal` mount as auth.
# ─────────────────────────────────────────────────────────────
template {
  source      = "/templates/akashic-api.tpl"
  destination = "/certs/akashic/.api-rendered"
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

# ─────────────────────────────────────────────────────────────
# Tenant portal: NO mTLS client cert.
#
# In Phase 8's three-server architecture, the portal talks to
# the API server (port 8082) using OAuth bearer tokens — not mTLS.
# The previous `portal-client.tpl` template was removed when the
# /users/* and /clients/* endpoints moved off the control plane onto
# the new bearer-authenticated API surface. The portal needs zero
# Akashic-internal trust material; it's a regular OAuth client.
# ─────────────────────────────────────────────────────────────
