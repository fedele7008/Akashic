# ═══════════════════════════════════════════════════════════════
# Policy: cert-issuer
# ═══════════════════════════════════════════════════════════════
# Scoped policy for Vault Agent to issue leaf certificates.
# Grants write access to issue endpoints on all PKI engines,
# and read access to CA chains for building trust bundles.
#
# Bound to the "cert-agent" AppRole used by vault-agent.
# ═══════════════════════════════════════════════════════════════

# --- Internal CA: issue server certs (postgres, redis, ldap, loki, akashic) ---
path "pki-internal/issue/*" {
  capabilities = ["create", "update"]
}

# --- mTLS: Control Plane ---
path "pki-mtls-akashic-ctrl/issue/*" {
  capabilities = ["create", "update"]
}

# --- mTLS: LDAP ---
path "pki-mtls-ldap/issue/*" {
  capabilities = ["create", "update"]
}

# --- mTLS: Loki ---
path "pki-mtls-loki/issue/*" {
  capabilities = ["create", "update"]
}

# --- Read CA chains (for building trust bundles) ---
path "pki-internal/cert/ca_chain" {
  capabilities = ["read"]
}
path "pki-mtls-akashic-ctrl/cert/ca_chain" {
  capabilities = ["read"]
}
path "pki-mtls-ldap/cert/ca_chain" {
  capabilities = ["read"]
}
path "pki-mtls-loki/cert/ca_chain" {
  capabilities = ["read"]
}
