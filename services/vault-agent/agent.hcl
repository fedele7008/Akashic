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
# Internal Server Certificates (pki-internal/server)
# ═══════════════════════════════════════════════════════════

# Control Server
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic/ctrl.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/ctrl.key"
  perms       = 0600
}

# Auth Server
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=auth.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic/auth.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=auth.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/auth.key"
  perms       = 0600
}

# PostgreSQL
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=postgres.akashic.local\" \"alt_names=postgres.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/postgres/postgres.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=postgres.akashic.local\" \"alt_names=postgres.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/postgres/postgres.key"
  perms       = 0600
}

# Redis
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=redis.akashic.local\" \"alt_names=redis.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/redis/redis.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=redis.akashic.local\" \"alt_names=redis.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/redis/redis.key"
  perms       = 0600
}

# LDAP
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/ldap/ldap.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/ldap/ldap.key"
  perms       = 0600
}

# Loki
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/loki/loki.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-internal/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/loki/loki.key"
  perms       = 0600
}

# ═══════════════════════════════════════════════════════════
# mTLS: Control Plane (pki-mtls-akashic-ctrl)
# ═══════════════════════════════════════════════════════════

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic/mtls-ctrl.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/server\" \"common_name=ctrl.akashic.local\" \"alt_names=localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/mtls-ctrl.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=cli.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic-cli/akashic-ctrl-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=cli.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic-cli/akashic-ctrl-client.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=bff.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/bff/akashic-ctrl-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-akashic-ctrl/issue/client\" \"common_name=bff.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/bff/akashic-ctrl-client.key"
  perms       = 0600
}

# ═══════════════════════════════════════════════════════════
# mTLS: LDAP (pki-mtls-ldap)
# ═══════════════════════════════════════════════════════════

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/ldap/mtls-ldap.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/server\" \"common_name=ldap.akashic.local\" \"alt_names=ldap.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/ldap/mtls-ldap.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic/ldap-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/ldap-client.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=phpldapadmin.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/phpldapadmin/ldap-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-ldap/issue/client\" \"common_name=phpldapadmin.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/phpldapadmin/ldap-client.key"
  perms       = 0600
}

# ═══════════════════════════════════════════════════════════
# mTLS: Loki (pki-mtls-loki)
# ═══════════════════════════════════════════════════════════

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/loki/mtls-loki.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/server\" \"common_name=loki.akashic.local\" \"alt_names=loki.akashic.local,localhost\" \"ip_sans=127.0.0.1\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/loki/mtls-loki.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/akashic/loki-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=akashic.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/akashic/loki-client.key"
  perms       = 0600
}

template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=grafana.akashic.local\" \"ttl=2160h\" }}{{ .Cert }}{{ end }}"
  destination = "/certs/grafana/loki-client.crt"
  perms       = 0644
}
template {
  contents    = "{{ with pkiCert \"pki-mtls-loki/issue/client\" \"common_name=grafana.akashic.local\" \"ttl=2160h\" }}{{ .Key }}{{ end }}"
  destination = "/certs/grafana/loki-client.key"
  perms       = 0600
}
