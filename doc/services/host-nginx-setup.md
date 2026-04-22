# Host-Level Reverse Proxy Setup Guide

This guide explains how to set up a host-level nginx reverse proxy in front of the Akashic project. This is **required** when exposing Akashic services to the network, because the Akashic internal proxy (port 8280) serves HTTP only -- basic auth credentials would be transmitted in plaintext without TLS termination.

## Overview

```
Browser (HTTPS)
  |
  v
Host nginx (port 443)         Terminates TLS, forwards to Akashic
  |                            Wildcard cert: *.akashic.example.com
  v
Akashic proxy (port 8280)     Subdomain routing, basic auth, rate limiting
  |
  +-- adminer.*  --> adminer
  +-- (more services added over time)
  +-- (default)  --> PKI endpoints / 403
```

The host nginx handles:
- TLS termination (HTTPS)
- HTTP-to-HTTPS redirect
- Forwarding the original `Host` header (critical for subdomain routing)

The Akashic proxy handles:
- Subdomain-based routing to Docker services
- Basic auth, rate limiting, and access control

## Prerequisites

### 1. A Domain Name

You need a domain (or subdomain) with wildcard DNS configured:

```
*.akashic.example.com  -->  your server IP
akashic.example.com    -->  your server IP
```

**How to configure wildcard DNS:**
- In your DNS provider, add two A records:
  - `akashic` -> `<your-server-ip>`
  - `*.akashic` -> `<your-server-ip>`
- Or if using a subdomain of an existing domain:
  - `akashic.yourdomain.com` -> `<your-server-ip>`
  - `*.akashic.yourdomain.com` -> `<your-server-ip>`

Verify with:
```bash
dig adminer.akashic.example.com
# Should resolve to your server IP
```

### 2. A TLS Certificate

You need a certificate that covers the wildcard subdomain. Options:

**Let's Encrypt (free, recommended):**
```bash
# Using certbot with DNS challenge (required for wildcards)
certbot certonly --manual --preferred-challenges dns \
  -d "akashic.example.com" \
  -d "*.akashic.example.com"
```

**Wildcard certificate from a commercial CA:**
- Request a certificate for `*.akashic.example.com` and `akashic.example.com`
- Both SAN entries are needed (wildcard doesn't cover the bare domain)

**Self-signed (development only):**
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout akashic.key -out akashic.crt \
  -subj "/CN=*.akashic.example.com" \
  -addext "subjectAltName=DNS:akashic.example.com,DNS:*.akashic.example.com"
```

### 3. nginx Installed on the Host

```bash
# Ubuntu/Debian
sudo apt install nginx

# macOS
brew install nginx

# Alpine
apk add nginx
```

## nginx Configuration

Create a config file for Akashic. The location depends on your OS:
- Ubuntu/Debian: `/etc/nginx/sites-available/akashic.conf` (symlink to `sites-enabled/`)
- macOS (Homebrew): `/opt/homebrew/etc/nginx/servers/akashic.conf`
- General: `/etc/nginx/conf.d/akashic.conf`

### Full Configuration

```nginx
# ---------------------------------------------------------------
# HTTP -> HTTPS redirect
# ---------------------------------------------------------------
server {
    listen       80;
    listen  [::]:80;
    server_name  akashic.example.com *.akashic.example.com;

    return 301 https://$host$request_uri;
}

# ---------------------------------------------------------------
# HTTPS reverse proxy to Akashic
# ---------------------------------------------------------------
server {
    listen       443 ssl;
    listen  [::]:443 ssl;
    http2 on;
    server_name  akashic.example.com *.akashic.example.com;

    # -- TLS certificates -----------------------------------------
    ssl_certificate     /path/to/akashic.crt;
    ssl_certificate_key /path/to/akashic.key;

    # -- TLS hardening --------------------------------------------
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache   shared:SSL:10m;

    # -- Proxy to Akashic -----------------------------------------
    location / {
        proxy_pass http://localhost:8280;

        # CRITICAL: Host header must be forwarded for subdomain routing
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (for future services that need it)
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_read_timeout 60s;
    }
}
```

Replace:
- `akashic.example.com` with your actual domain
- `/path/to/akashic.crt` and `.key` with your certificate paths

### Configuration Explained

| Directive | Purpose |
|-----------|---------|
| `listen 80` + `return 301` | Redirects all HTTP traffic to HTTPS |
| `server_name *.akashic.example.com` | Matches all subdomains (adminer.*, grafana.*, etc.) |
| `ssl_protocols TLSv1.2 TLSv1.3` | Disables older, insecure TLS versions |
| `ssl_prefer_server_ciphers off` | Lets the client choose the cipher (modern best practice) |
| `ssl_session_cache shared:SSL:10m` | Caches TLS sessions for performance (10MB = ~40,000 sessions) |
| `proxy_set_header Host $host` | **Required.** Forwards the original Host header so the Akashic proxy can match subdomains |
| `proxy_set_header X-Forwarded-Proto $scheme` | Tells upstream the original protocol was HTTPS |
| `proxy_http_version 1.1` + `Upgrade` | Enables WebSocket passthrough for services that need it |

### Upstream Address

The `proxy_pass` address depends on how nginx reaches the Akashic proxy:

| Setup | `proxy_pass` value |
|-------|-------------------|
| nginx on the same host as Docker | `http://localhost:8280` |
| nginx in Docker (same network) | `http://proxy:8280` or `http://proxy.akashic.local:8280` |
| nginx in Docker (different host) | `http://host.docker.internal:8280` |
| nginx on a different machine | `http://<docker-host-ip>:8280` |

If you are running the host nginx inside Docker, you can use an environment variable for flexibility:

```nginx
proxy_pass http://${AKASHIC_UPSTREAM};
```

And set `AKASHIC_UPSTREAM=host.docker.internal:8280` (or `localhost:8280`) in your nginx container's environment.

## Applying the Configuration

```bash
# Test the config
sudo nginx -t

# Reload nginx (no downtime)
sudo nginx -s reload
```

## Verification

After setup, verify each layer works:

```bash
# 1. HTTP redirect works
curl -I http://adminer.akashic.example.com
# Expected: 301 -> https://adminer.akashic.example.com/

# 2. HTTPS terminates correctly
curl -I https://adminer.akashic.example.com
# Expected: 401 Unauthorized (if basic auth configured)
# Expected: 200 (if basic auth not configured)

# 3. Basic auth works (if configured)
curl -u admin:yourpassword https://adminer.akashic.example.com/
# Expected: 200 (Adminer HTML)

# 4. PKI endpoints work (no subdomain needed)
curl https://akashic.example.com/v1/pki-root/ca/pem
# Expected: PEM certificate

# 5. Unknown paths are blocked
curl https://akashic.example.com/anything
# Expected: 403 {"error": "forbidden"}
```

## Certificate Renewal

### Let's Encrypt (automated)

If using certbot, set up auto-renewal:

```bash
# Test renewal
sudo certbot renew --dry-run

# certbot typically installs a cron/systemd timer automatically.
# Verify:
systemctl list-timers | grep certbot
```

After renewal, reload nginx to pick up the new cert:

```bash
sudo nginx -s reload
```

Or configure a post-renewal hook:
```bash
# /etc/letsencrypt/renewal-hooks/post/reload-nginx.sh
#!/bin/sh
nginx -s reload
```

### Manual Certificates

Replace the cert files and reload:
```bash
sudo cp new-cert.crt /path/to/akashic.crt
sudo cp new-cert.key /path/to/akashic.key
sudo nginx -s reload
```

## Common Issues

**"502 Bad Gateway":**
- The Akashic proxy isn't running. Check: `docker compose ps proxy`
- Wrong upstream address. Verify `proxy_pass` points to the correct host/port.

**"403 Forbidden" on adminer subdomain:**
- The `Host` header isn't being forwarded. Ensure `proxy_set_header Host $host;` is present.
- Wildcard DNS not configured. Verify: `dig adminer.akashic.example.com`

**"SSL: error" / certificate warnings:**
- Certificate doesn't cover the wildcard. Check: `openssl s_client -connect adminer.akashic.example.com:443 -servername adminer.akashic.example.com`
- Wrong certificate path in nginx config.

**Browser shows "Not Secure" despite HTTPS:**
- Using a self-signed cert. Import the CA into your browser's trust store, or use Let's Encrypt for a publicly trusted cert.

## Not Using nginx?

The same principles apply to any reverse proxy. The critical requirements are:

1. **TLS termination** on port 443
2. **HTTP-to-HTTPS redirect** on port 80
3. **Forward the `Host` header** to the upstream (port 8280)
4. **Wildcard domain matching** for `*.akashic.example.com`

### Caddy (auto-HTTPS)

```
*.akashic.example.com, akashic.example.com {
    reverse_proxy localhost:8280
}
```

Caddy automatically handles TLS certificates via Let's Encrypt.

### Traefik

```yaml
# traefik.yml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
  websecure:
    address: ":443"

# dynamic config
http:
  routers:
    akashic:
      rule: "HostRegexp(`{subdomain:.+}.akashic.example.com`)"
      service: akashic
      tls:
        certResolver: letsencrypt
  services:
    akashic:
      loadBalancer:
        servers:
          - url: "http://localhost:8280"
```
