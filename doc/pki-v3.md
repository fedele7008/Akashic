# Akashic PKI Configuration Guide

This document summarises the public key infrastructure (PKI) setup for Akashic deployments. It lists the certificate authority (CA) expectations, TLS requirements, and client trust bundles for each service interaction.

## CA Overview

| CA | Purpose | Typical Issuer Chain |
| --- | --- | --- |
| RootCA | Offline/long-lived Akashic root that signs internal subordinate CAs. | `RootCA`
| InternalCA | Subordinate CA for non-public Akashic services. | `RootCA -> InternalCA -> <service>.cert`
| PublicCA | Publicly trusted CA (commercial or dev self-signed) for internet-facing services. | `PublicCA -> <service>.cert`
| mTLS-Ctrl CA | Subordinate CA for control plane mTLS client authentication (CLI, BFF). | `RootCA -> InternalCA -> mTLS-Ctrl CA -> <client>.cert`

> **Note:** mTLS is only used for the control plane (CLI/BFF -> Akashic Control Server). LDAP and Loki use server-side TLS only. If external LDAP/Loki connections require mTLS in the future, dedicated mTLS CAs can be added back.

> **Trusted bundle**: Always include every CA (RootCA, InternalCA, or PublicCA) required to validate upstream certificates used by a service.

## Connection Guidelines

### Control and Auth
- **Control <-> Auth**: Same process and runtime. In-memory channels are sufficient -- no TLS is required.

### Datastores
| Client -> Server | TLS Expectation | Certificates | Client Requirements |
| --- | --- | --- | --- |
| Control/Auth -> PostgresDB | Optional when localhost-only | `RootCA -> InternalCA -> postgres.cert` | Load trusted bundle containing RootCA/InternalCA. |
| Adminer -> PostgresDB | Optional when localhost-only | `RootCA -> InternalCA -> postgres.cert` | Load trusted bundle to verify Postgres. |
| Control/Auth -> Redis | Optional when localhost-only | `RootCA -> InternalCA -> redis.cert` | Load trusted bundle containing RootCA/InternalCA. |

### Directory Services
| Client -> Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| Control/Auth -> OpenLDAP | Optional when internal-only | `RootCA -> InternalCA -> ldap.cert` | Load trusted bundle (include RootCA/InternalCA). |
| phpLDAPadmin -> OpenLDAP | Optional when internal-only | `RootCA -> InternalCA -> ldap.cert` | Load trusted bundle. |
| Browser -> phpLDAPadmin | TLS required in production | `PublicCA -> phpldapadmin.cert` | Browser must trust issuing PublicCA. |

### Logging Stack
| Client -> Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| Control/Auth -> Loki | Optional when internal-only | `RootCA -> InternalCA -> loki.cert` | Load trusted bundle (include RootCA/InternalCA). |
| Grafana -> Loki | Optional when internal-only | `RootCA -> InternalCA -> loki.cert` | Load trusted bundle. |
| Browser -> Grafana | TLS required in production | `PublicCA -> grafana.cert` | Browser must trust issuing PublicCA. |

### Web and BFF Layer
| Client -> Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| BFF -> Control | mTLS strongly recommended | `RootCA -> InternalCA -> akashic-ctrl.cert` | Load trusted bundle + `bff-akashic-client.cert` (mTLS). |
| BFF -> Auth | TLS required in production | `PublicCA -> akashic-auth.cert` | Load trusted public root bundle. |
| WEB -> BFF | TLS required in production | `PublicCA -> bff.cert` | Load trusted bundle. |
| Browser -> WEB | TLS required | `PublicCA -> web.cert` | Browser must trust issuing PublicCA. |

### CLI Interactions
| Client -> Server | TLS Requirement | Certificates | Client Requirements |
| --- | --- | --- | --- |
| AkashicCLI -> Control | mTLS strongly recommended | `RootCA -> InternalCA -> akashic-ctrl.cert` | Load trusted bundle + `cli-akashic-client.cert` (mTLS). |
| AkashicCLI -> Auth | TLS required in production | `PublicCA -> akashic-auth.cert` | Load trusted public root bundle. |

### Additional Notes
- **TLS Optional** indicates that deployments limited to localhost can omit TLS, but enabling TLS is advised for consistency.
- **mTLS** is only required for the control plane (CLI and BFF client authentication). LDAP and Loki connections use server-side TLS with password/bind authentication.
- **Development environments** can rely on locally trusted self-signed "public" roots; production deployments should use publicly trusted CAs for any internet-facing service.
