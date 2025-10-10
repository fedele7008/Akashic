# Akashic PKI Configuration Guide

This document summarises the recommended public key infrastructure (PKI) setup for Akashic deployments. It lists the certificate authority (CA) expectations, TLS/mTLS requirements, and client trust bundles for each service interaction.

## CA Overview

| CA | Purpose | Typical Issuer Chain |
| --- | --- | --- |
| RootCA | Offline/long-lived Akashic root that signs internal subordinate CAs. | `RootCA`
| InternalCA | Subordinate CA for non-public Akashic services. | `RootCA -> InternalCA -> <service>.cert`
| ExternalRoot (ExternCA) | Customer-provided trusted root for replaceable internal services when available. | `ExternCA -> <service>.cert`
| PublicCA | Publicly trusted CA (commercial or dev self-signed) for internet-facing services. | `PublicCA -> <service>.cert`

> **Trusted bundle**: Always include every CA (RootCA, InternalCA, ExternCA, or PublicCA) required to validate upstream certificates used by a service.

## Connection Guidelines

### Control and Auth
- **Control ↔ Auth**: Same process and runtime. In-memory channels are sufficient—no TLS is required.

### Datastores
| Client → Server | Component Type | TLS Expectation | Certificates | Client Requirements |
| --- | --- | --- | --- | --- |
| Control/Auth → PostgresDB | Non-replaceable internal | Optional when localhost-only | `RootCA -> InternalCA -> postgres.cert` | Load trusted bundle containing RootCA/InternalCA. |
| Adminer → PostgresDB | Non-replaceable internal | Optional when localhost-only | `RootCA -> InternalCA -> postgres.cert` | Load `root-bundle.pem` to verify Postgres. |
| Control/Auth → Redis | Non-replaceable internal | Optional when localhost-only | `RootCA -> InternalCA -> redis.cert` | Load trusted bundle containing RootCA/InternalCA. |

### Directory Services
| Client → Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| Control/Auth → OpenLDAP | Optional when internal-only; enable TLS/mTLS when required | - If no `externalRoot`: `RootCA -> InternalCA -> ldap.cert`<br>- If `externalRoot` provided: `ExternCA -> ldap.cert` | - Always load trusted bundle (include RootCA/InternalCA or ExternCA).<br>- For mTLS load `akashic-ldap-client.cert`. |
| phpLDAPadmin → OpenLDAP | Optional when internal-only; enable TLS/mTLS when required | Same as above | - Load trusted bundle.<br>- For mTLS load `phpldapadmin-ldap-client.cert`. |
| Browser → phpLDAPadmin | TLS required in production | `PublicCA -> phpldapadmin.cert` (self-signed acceptable for dev if trusted locally) | - If phpLDAPadmin connects to OpenLDAP with mTLS, it also needs its own client certificate/key for that connection. |

### Logging Stack
| Client → Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| Control/Auth → Loki | Optional when internal-only; enable TLS/mTLS when required | - If no `externalRoot`: `RootCA -> InternalCA -> loki.cert`<br>- If `externalRoot` provided: `ExternCA -> loki.cert` | - Load trusted bundle (include RootCA/InternalCA or ExternCA).<br>- For mTLS load `akashic-loki-client.cert`. |
| Grafana → Loki | Optional when internal-only; enable TLS/mTLS when required | Same as above | - Load trusted bundle.<br>- For mTLS load `grafana-loki-client.cert`. |
| Browser → Grafana | TLS required in production | `PublicCA -> grafana.cert` (self-signed public CA acceptable for dev) | Browser must trust issuing PublicCA. |

### Web and BFF Layer
| Client → Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| BFF → Control | Optional when internal-only; mTLS strongly recommended | `RootCA -> InternalCA -> akashic-ctrl.cert` | - Load trusted bundle.<br>- For mTLS load `bff-akashic-client.cert`. |
| BFF → Auth | TLS required in production | `PublicCA -> akashic-auth.cert` | Load trusted public root bundle. |
| WEB → BFF | TLS required in production | `PublicCA -> bff.cert` | - WEB must load trusted bundle to verify Akashic (RootCA/InternalCA) when acting as client.<br>- BFF, as client to Akashic, should also use the same trusted bundle. |
| Browser → WEB | TLS required | `PublicCA -> web.cert` | Browser must trust issuing PublicCA. |
| WEB → Control | Not permitted when BFF is bypassed (security restriction). | — | — |
| WEB → Auth | TLS required in production | `PublicCA -> akashic-auth.cert` | Load trusted public root bundle. |

### CLI Interactions
| Client → Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| AkashicCLI → Control | Optional when internal-only; mTLS strongly recommended | `RootCA -> InternalCA -> akashic-ctrl.cert` | Load trusted bundle and `cli-akashic-client.cert` for mTLS. |
| AkashicCLI → Auth | TLS required in production | `PublicCA -> akashic-auth.cert` | Load trusted public root bundle. |

### Additional Notes
- **TLS Optional** indicates that deployments limited to localhost can omit TLS, but enabling TLS is advised for consistency.
- **mTLS** requires both client and server certificates; the client certificates are explicitly listed above.
- **Development environments** can rely on locally trusted self-signed “public” roots; production deployments should use publicly trusted CAs for any internet-facing service.
