# Akashic PKI Configuration Guide

This document summarizes the recommended certificate authorities (CAs),
server certificates, and mutual TLS (mTLS) options for common connections in
an Akashic deployment. Use it as a checklist when provisioning certificates
and configuring trust stores.

## Legend

- **Internal non-replaceable** – Core Akashic component. You may rely on
  Akashic's self-signed internal CA chain unless the service is exposed
  outside the host.
- **Internal replaceable** – Third-party service that can be swapped. Prefer
  self-signed internal CAs for purely internal traffic, or bring your own
  CA when integrating external services.
- **External/public** – Exposed to users or the public internet. Always use a
  publicly trusted CA in production.
- **Trusted bundle** – The trust store loaded by clients. Include the
  relevant root(s) and intermediate(s).

## Core Control Plane Traffic

| Connection | Service role | TLS guidance | Certificate chain | Client certs (for mTLS) | Notes |
|------------|--------------|--------------|-------------------|-------------------------|-------|
| Control ↔ Auth | Internal non-replaceable | Runs in-process using in-memory channels | _None required_ | _N/A_ | Network TLS not needed because the services share a process. |
| Control/Auth → PostgresDB | Internal non-replaceable | TLS optional when Postgres is localhost-only | RootCA → InternalCA → `postgres.cert` | Optional `akashic-postgres-client.cert` if you enable mTLS | Use the internal CA chain unless exposing Postgres externally. |
| Control/Auth → Redis | Internal non-replaceable | TLS optional when Redis is localhost-only | RootCA → InternalCA → `redis.cert` | Optional `akashic-redis-client.cert` for mTLS | Same policy as Postgres. |
| Control/Auth → OpenLDAP | Replaceable internal | TLS/mTLS optional if strictly internal | If no external root: RootCA → InternalCA → `ldap.cert`<br>If external root provided: ExternalRoot → `ldap.cert` | `akashic-ldap-client.cert` when mTLS | Add ExternalRoot to the trusted bundle when using external CA. |
| Control/Auth → Loki | Replaceable internal | TLS/mTLS optional if strictly internal | If no external root: RootCA → InternalCA → `loki.cert`<br>If external root provided: ExternalRoot → `loki.cert` | `akashic-loki-client.cert` when mTLS | Update trusted bundle with ExternalRoot when supplied. |
| AkashicCLI → Control | Internal non-replaceable | TLS strongly recommended; mTLS recommended | RootCA → InternalCA → `akashic-ctrl.cert` | `cli-akashic-client.cert` | CLI must trust the internal bundle. |
| AkashicCLI → Auth | External (prod) | TLS required in production | PublicCA → `akashic-auth.cert` | Optional client cert for mTLS | Prefer a publicly trusted CA to simplify distribution. |
| BFF → Control | Internal non-replaceable | TLS strongly recommended; mTLS recommended | RootCA → InternalCA → `akashic-ctrl.cert` | `bff-akashic-client.cert` | Ensure BFF trusts the internal bundle. |
| BFF → Auth | External (prod) | TLS required in production | PublicCA → `akashic-auth.cert` | Optional | Use public CA to avoid browser warnings when debugging via BFF. |
| WEB → Control | — | **Access prohibited** | — | — | SPA deployments must not contact Control directly. |
| WEB → Auth | External (prod) | TLS required | PublicCA → `akashic-auth.cert` | Optional | Required when BFF is bypassed. |

## Directory Management

| Connection | Service role | TLS guidance | Certificate chain | Client certs (for mTLS) | Notes |
|------------|--------------|--------------|-------------------|-------------------------|-------|
| phpLDAPadmin → OpenLDAP | Replaceable internal | TLS/mTLS optional if internal-only | Self-signed internal CA or ExternalRoot (match LDAP config) | `phpldapadmin-ldap-client.cert` for mTLS | phpLDAPadmin must load the trusted bundle used by OpenLDAP. |
| Browser → phpLDAPadmin | External (prod) | TLS required in production | PublicCA → `phpldapadmin.cert` (self-signed public CA acceptable for dev) | — | phpLDAPadmin must also load its LDAP client keys when LDAP uses mTLS. |

## Observability Stack

| Connection | Service role | TLS guidance | Certificate chain | Client certs (for mTLS) | Notes |
|------------|--------------|--------------|-------------------|-------------------------|-------|
| Grafana → Loki | Replaceable internal | TLS/mTLS optional if internal-only | Self-signed internal CA or ExternalRoot (match Loki config) | `grafana-loki-client.cert` for mTLS | Grafana must import the trusted bundle to verify Loki. |
| Browser → Grafana | External (prod) | TLS required | PublicCA → `grafana.cert` (self-signed public CA acceptable for dev) | — | Browsers require publicly trusted certificates outside dev. |

## Database Tools

| Connection | Service role | TLS guidance | Certificate chain | Client certs (for mTLS) | Notes |
|------------|--------------|--------------|-------------------|-------------------------|-------|
| Adminer → PostgresDB | Internal non-replaceable | TLS optional when localhost-only | RootCA → InternalCA → `postgres.cert` | Optional `adminer-postgres-client.cert` for mTLS | Adminer must trust `root-bundle.pem` to verify Postgres. |
| Browser → Adminer | Internal replaceable | Typically localhost-only; TLS/mTLS not required | — | — | Keep Adminer bound to localhost to avoid public exposure. |

## Web Front-End Flow

| Connection | Service role | TLS guidance | Certificate chain | Client certs (for mTLS) | Notes |
|------------|--------------|--------------|-------------------|-------------------------|-------|
| WEB → BFF | BFF as server (external) | TLS required in production | PublicCA → `bff.cert` | — | BFF must also trust Akashic's internal bundle when acting as a client. |
| Browser → WEB | External (prod) | TLS required | PublicCA → `web.cert` (self-signed public CA acceptable for dev) | — | Ensure front-end certificates chain to a trusted public root. |

## Trust Bundle Management Checklist

1. **Internal bundle** – Include RootCA and InternalCA. Distribute to
   Control, Auth, BFF, CLI, Adminer, Grafana, Loki, Redis, Postgres, and any
   other internal clients.
2. **External/partner bundle** – When integrating ExternalRoot-signed
   certificates (for OpenLDAP or Loki), append ExternalRoot to the bundle and
   update clients that need to trust it.
3. **Public bundle** – Use the system trust store or a dedicated bundle with
   PublicCA roots for services exposed to browsers or public clients.
4. **Client certificates** – Store mTLS client key pairs securely and deploy
   them only to the clients that require them (CLI, BFF, Grafana, phpLDAPadmin,
   etc.). Rotate them regularly.
5. **Environment overrides** – For development, you may substitute
   self-signed public roots that are manually trusted on developer machines.
   Ensure production uses publicly trusted roots.

Refer to the architecture diagram when mapping certificates to services to
confirm which components communicate and where each certificate must reside.
