# Akashic PKI Configuration Guide

This document summarizes the recommended certificate authority (CA) hierarchy and certificate usage for the Akashic platform. It focuses on how each component should establish TLS or mutual TLS (mTLS) channels in both production and development environments.

## CA Hierarchy Overview

| CA Type | Intended Scope | Typical Usage |
| --- | --- | --- |
| **Root CA** | Offline anchor for all internally managed certificates. | Signs the Internal CA. |
| **Internal CA** | Issues certificates for non-public Akashic services. | Signs certificates for Control, Auth (internal endpoints), Postgres, Redis, OpenLDAP, Loki, etc. |
| **External Root (ExternCA)** | When an organization provides its own root for internal services. | Signs replaceable components that must chain to organization CA. |
| **Public CA** | Publicly trusted certificate authorities (or a dev-only self-signed equivalent). | Signs certificates for user-facing services exposed to the public internet (Auth, BFF, WEB, Grafana, phpLDAPadmin, etc.). |

> **Trusted Bundles**: Any component acting as a client must trust the issuing CA of the server’s certificate. Add the relevant root(s) to a bundle (e.g., `bundle.pem`) and configure the client to verify the server.

## Connection Matrix

The following sections describe the recommended certificates and trust bundles for each communication path. Use the provided CA hierarchy to issue the certificates unless an external root is explicitly required.

### Control ↔ Auth
- These services run within the same process space, communicating through in-memory channels; TLS is not required.

### Control/Auth → PostgresDB
- Postgres is an internal, non-replaceable component; TLS is optional if bound to localhost.
- Recommended certificate chain: `RootCA → InternalCA → postgres.cert`.
- Clients (Control/Auth) should trust the Internal CA when TLS is enabled.

### Control/Auth → Redis
- Redis is an internal, non-replaceable component; TLS is optional if bound to localhost.
- Recommended certificate chain: `RootCA → InternalCA → redis.cert`.
- Clients should trust the Internal CA if TLS is enabled.

### Control/Auth → OpenLDAP
- OpenLDAP is a replaceable internal component.
- **Default (no external root provided)**: `RootCA → InternalCA → ldap.cert`.
- **With external root (`externalRoot`)**: `ExternCA → ldap.cert` and add `externalRoot` to the client trust bundle.
- For mTLS, provision `akashic-ldap-client.cert` to Control/Auth.

### phpLDAPadmin → OpenLDAP
- Treats OpenLDAP as replaceable. TLS is optional if isolated to localhost.
- Accepts either Internal CA (`RootCA → InternalCA → ldap.cert`) or External Root.
- phpLDAPadmin must load the corresponding trusted bundle.
- For mTLS, phpLDAPadmin must present `phpldapadmin-ldap-client.cert`.

### Browser → phpLDAPadmin
- phpLDAPadmin is an externally accessible, replaceable component; TLS is required in production.
- Use a public CA: `PublicCA → phpldapadmin.cert`.
- If phpLDAPadmin talks to OpenLDAP using mTLS, ensure it loads its own client cert and key.
- For development, a self-signed public CA trusted by the developer machine is acceptable.

### Control/Auth → Loki
- Loki is a replaceable internal component.
- **Default**: `RootCA → InternalCA → loki.cert`.
- **With external root**: `ExternCA → loki.cert` and add `externalRoot` to the Akashic trust bundle.
- For mTLS, configure `akashic-loki-client.cert` for Control/Auth.

### Grafana → Loki
- Grafana must trust Loki’s certificate, issued either by the Internal CA or an external root.
- Load the appropriate trusted bundle in Grafana.
- For mTLS, Grafana presents `grafana-loki-client.cert`.

### Browser → Grafana
- Grafana is a replaceable external component; TLS is required.
- Use `PublicCA → grafana.cert` (or a trusted self-signed public CA for development).

### Adminer → PostgresDB
- Postgres retains the internal certificate strategy: `RootCA → InternalCA → postgres.cert`.
- Adminer must load `root-bundle.pem` (Internal CA or relevant CA bundle) to validate the server certificate.

### Browser → Adminer
- Adminer should be accessible only on localhost for administration; TLS/mTLS is generally unnecessary.

### AkashicCLI → Control
- Control is non-replaceable but mTLS is strongly recommended even internally.
- Use `RootCA → InternalCA → akashic-ctrl.cert` for the server.
- Provide the CLI with `cli-akashic-client.cert` to authenticate with Control via mTLS.

### AkashicCLI → Auth
- Auth is an external-facing component; TLS is required in production.
- Prefer public certificates: `PublicCA → akashic-auth.cert`.

### BFF → Control
- Control server uses `RootCA → InternalCA → akashic-ctrl.cert`.
- BFF must trust the Internal CA and present `bff-akashic-client.cert` when mTLS is enabled (strongly recommended).

### BFF → Auth
- Auth is external-facing; require TLS with `PublicCA → akashic-auth.cert`.

### WEB → BFF
- BFF acts both as a server (for WEB) and a client (toward Akashic services).
- **Server role**: Issue `PublicCA → bff.cert` so browser-based JavaScript can connect securely.
- **Client role**: Load the trusted bundle that includes the Internal CA for calls to Akashic services.

### Browser → WEB
- WEB is a public-facing front-end server; TLS is required.
- Use `PublicCA → web.cert` (or trusted dev self-signed CA during development).

### WEB → Control
- Direct access from WEB to Control is prohibited for security reasons when BFF is bypassed.

### WEB → Auth
- When using SPA WEB without BFF, Auth remains external and must present `PublicCA → akashic-auth.cert`.

## Implementation Tips

1. **Certificate Storage**: Keep CA private keys secure and offline whenever possible. Automate certificate issuance through a secure PKI toolchain.
2. **Bundles**: Standardize bundle names (e.g., `root-bundle.pem`, `trusted-bundle.pem`) so that components can share configuration defaults.
3. **Rotation**: Document rotation procedures for each certificate. Maintain short lifetimes for leaf certificates (e.g., 90 days) and longer lifetimes for CAs.
4. **Development vs. Production**: For development, a single self-signed “public” CA trusted by developer machines can simplify setup while maintaining TLS flows.
5. **mTLS Policies**: Where mTLS is optional but recommended, define environment toggles (e.g., `ENABLE_MTLS=true`) and ship client certificates with restricted permissions.
