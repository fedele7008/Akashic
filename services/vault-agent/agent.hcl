vault {
  address = "https://vault:8200"
  ca_cert = "/certs/vault/root-ca.crt"
}

auto_auth {
  method "token_file" {
    config = {
      token_file_path = "/vault/token/vault/root-token"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-agent-token"
    }
  }
}

template_config {
  exit_on_retry_failure = true
}

# ═══════════════════════════════════════════════════════════
# Each template writes a PEM bundle (cert+key), then the
# command splits it into separate .crt and .key files.
# This ensures cert and key always match (same issuance).
# ═══════════════════════════════════════════════════════════

# --- Internal Server Certs (pki-internal/server) ---

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/ctrl.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic/ctrl.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=auth.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/auth.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic/auth.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=postgres.akashic.local\" \"alt_names=postgres.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/postgres/postgres.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/postgres/postgres.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=redis.akashic.local\" \"alt_names=redis.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/redis/redis.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/redis/redis.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/ldap/ldap.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/ldap/ldap.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/loki/loki.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/loki/loki.bundle"
}

# --- mTLS: Control Plane (pki-mtls-akashic-ctrl) ---

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/mtls-ctrl.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic/mtls-ctrl.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=cli.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic-cli/akashic-ctrl-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic-cli/akashic-ctrl-client.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=bff.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/bff/akashic-ctrl-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/bff/akashic-ctrl-client.bundle"
}

# --- mTLS: LDAP (pki-mtls-ldap) ---

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/ldap/mtls-ldap.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/ldap/mtls-ldap.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/ldap-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic/ldap-client.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=phpldapadmin.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/phpldapadmin/ldap-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/phpldapadmin/ldap-client.bundle"
}

# --- mTLS: Loki (pki-mtls-loki) ---

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/loki/mtls-loki.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/loki/mtls-loki.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/loki-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/akashic/loki-client.bundle"
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=grafana.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ .Key }}{{ end }}"
  destination = "/certs/grafana/loki-client.bundle"
  perms       = 0600
  command     = "/config/split-bundle.sh /certs/grafana/loki-client.bundle"
}
