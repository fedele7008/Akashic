# Akashic Architecture

**Version:** 0.0.2
**Last Updated:** October 9, 2025

## Table of Contents

1. [Overview](#overview)
2. [Network Architecture](#network-architecture)
3. [SSL/TLS Configuration](#ssltls-configuration)
4. [Deployment Scenarios](#deployment-scenarios)
5. [Certificate Management](#certificate-management)
6. [Service Components](#service-components)
7. [Configuration Strategy](#configuration-strategy)

---

## Overview

Akashic is a Service Registration-based SSO (Single Sign-On) system implementing OAuth 2.1, OIDC, and LDAP IDP functionality. The architecture is designed for flexible deployment with support for both bundled services and BYOX (Bring Your Own X) integration.

### Core Design Principles

1. **Flexible Deployment**: Support for default bundled services or external integrations (BYOLDAP, BYOBFF, BYOWeb)
2. **Zero-Config Setup**: Clone → Docker Compose → Run (no manual certificate generation or configuration)
3. **Security First**: TLS/mTLS by default with optional disable for specific scenarios
4. **Modular Architecture**: Monolithic with decoupled modules, designed for future MSA migration
5. **Production Ready**: Environment-driven configuration with comprehensive observability

---

## Network Architecture

### Service Communication Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Client Browser                                  │
└─────────────────────────────────────────────────────────────────────────┘
           │                                    │
           │ HTTPS (optional)                   │ HTTPS/HTTP
           │                                    │
           ▼                                    ▼
┌──────────────────────┐            ┌──────────────────────┐
│   Web Frontend       │            │   Auth Server        │
│   (React/Vue/etc)    │◄──────────►│   (OAuth/OIDC)       │
│                      │  API Call  │   Port: 8080         │
│   Port: 3000         │            │                      │
└──────────────────────┘            └──────────────────────┘
           │                                    ▲
           │ HTTPS (optional)                   │
           │                                    │
           ▼                                    │
┌──────────────────────┐                       │
│   BFF (Backend       │                       │
│   For Frontend)      │                       │
│                      │                       │
│   Stores: Sessions,  │                       │
│   Tokens, State      │                       │
└──────────────────────┘                       │
           │                                    │
           │ mTLS (mutual TLS)                  │
           │ Client Cert Required               │
           │                                    │
           ▼                                    │
┌──────────────────────────────────────────────┴──────────┐
│              Akashic IDP Server                          │
│                                                           │
│  ┌─────────────────┐         ┌──────────────────────┐   │
│  │ Control Server  │         │   Auth Server        │   │
│  │ (Management)    │         │   (OAuth/OIDC)       │   │
│  │                 │         │                      │   │
│  │ Port: 8081      │         │   Port: 8080         │   │
│  │ TLS + mTLS      │         │   TLS (optional)     │   │
│  └─────────────────┘         └──────────────────────┘   │
│           │                                              │
│           │ Internal Communication                       │
│           │                                              │
└───────────┼──────────────────────────────────────────────┘
            │
            │ LDAPS/LDAP (TLS optional)
            │
            ▼
┌──────────────────────┐
│   LDAP Server        │
│   (User Directory)   │
│                      │
│   Ports: 389, 636    │
└──────────────────────┘
```

### Communication Patterns

#### 1. Web Frontend ↔ Auth Server (SPA Mode)
- **Protocol**: HTTPS/HTTP
- **Purpose**: Direct authentication for Single Page Applications
- **SSL**: Optional (enable/disable via config)
- **Flow**: User login → OAuth flow → Token issuance

#### 2. Web Frontend ↔ BFF (Traditional Web App Mode)
- **Protocol**: HTTPS/HTTP
- **Purpose**: Session-based authentication with backend state management
- **SSL**: Optional (recommended for production)
- **Flow**: User login → BFF manages OAuth → Session cookie

#### 3. BFF ↔ Akashic Control Server
- **Protocol**: mTLS (Mutual TLS)
- **Purpose**: Administrative operations (user management, policy changes, config updates)
- **SSL**: Optional (but highly recommended)
- **Requirements**:
  - BFF must have client certificate signed by Akashic CA
  - Control server verifies client certificate
  - Control server listens on localhost or restricted IP by default
- **Flow**: Admin action → BFF authenticates with client cert → Control API

#### 4. Akashic ↔ LDAP Server
- **Protocol**: LDAPS (LDAP over TLS) or plain LDAP
- **Purpose**: User authentication and directory queries
- **SSL**: Optional (enable/disable via config)
- **Important**: LDAP communicates **ONLY** with Akashic, **NOT** with BFF
- **Flow**: User login → Akashic queries LDAP → Returns auth result

#### 5. Akashic CLI ↔ Control Server
- **Protocol**: mTLS (Mutual TLS)
- **Purpose**: Command-line administration
- **Requirements**:
  - CLI must have client certificate (`certs/clients/cli.crt`)
  - Same mTLS requirements as BFF
- **Flow**: `akashic cli ...` → Authenticates with client cert → Control API

---

## SSL/TLS Configuration

### Configuration Matrix

All SSL/TLS connections can be independently enabled or disabled via configuration. This table shows the available options:

| Connection | Protocol | Enable/Disable | Config Location | Production Recommendation |
|-----------|----------|----------------|-----------------|---------------------------|
| **Control Server** | TLS + mTLS | `server.control.tls.enabled` | `config.yaml` | **REQUIRED** |
| **Auth Server** | TLS | `server.auth.tls.enabled` | `config.yaml` | **REQUIRED** |
| **LDAP → Akashic** | LDAPS | `ldap.use_tls` | `config.yaml` | **REQUIRED** |
| **BFF → Akashic** | mTLS | `server.control.tls.client_auth_required` | `config.yaml` | **REQUIRED** |
| **Web → BFF** | HTTPS | BFF configuration | BFF's config | **REQUIRED** |
| **Web → Auth** | HTTPS | `server.auth.tls.enabled` | `config.yaml` | Optional (if behind reverse proxy) |

### SSL Configuration Examples

#### Development (Localhost)

```yaml
# config.yaml - Relaxed SSL for local development
server:
  control:
    tls:
      enabled: true           # Keep mTLS for testing
      client_auth_required: true
  auth:
    tls:
      enabled: false          # No TLS for easier debugging

ldap:
  use_tls: false              # Plain LDAP on localhost
  tls_skip_verify: true       # If TLS enabled, skip verification
```

#### Staging

```yaml
# config.yaml - Balanced security for staging
server:
  control:
    tls:
      enabled: true
      client_auth_required: true
  auth:
    tls:
      enabled: true           # TLS for auth server

ldap:
  use_tls: true               # LDAPS enabled
  tls_skip_verify: false      # Proper certificate verification
  tls_ca_file: "./certs/ca/ca.crt"
```

#### Production

```yaml
# config.yaml - Maximum security for production
server:
  control:
    tls:
      enabled: true
      client_auth_required: true
      cert_file: "./certs/servers/control.crt"
      key_file: "./certs/servers/control.key"
      ca_file: "./certs/ca/ca.crt"
  auth:
    tls:
      enabled: true
      cert_file: "./certs/servers/auth.crt"
      key_file: "./certs/servers/auth.key"

ldap:
  use_tls: true
  tls_skip_verify: false
  tls_ca_file: "./certs/ca/ca.crt"
```

### Certificate Verification Modes

#### Control Server (mTLS)

```yaml
# Mode 1: No TLS (Development Only)
server.control.tls.enabled: false

# Mode 2: TLS Only (No Client Auth)
server.control.tls.enabled: true
server.control.tls.client_auth_required: false

# Mode 3: Full mTLS (Production)
server.control.tls.enabled: true
server.control.tls.client_auth_required: true
```

#### LDAP Connection

```yaml
# Mode 1: Plain LDAP (Development Only)
ldap.use_tls: false

# Mode 2: TLS with Skip Verify (NOT RECOMMENDED)
ldap.use_tls: true
ldap.tls_skip_verify: true

# Mode 3: TLS with CA Verification (Production)
ldap.use_tls: true
ldap.tls_skip_verify: false
ldap.tls_ca_file: "./certs/ca/ca.crt"

# Mode 4: TLS with System CA Pool (External LDAP)
ldap.use_tls: true
ldap.tls_skip_verify: false
ldap.tls_ca_file: ""  # Uses system CA pool
```

---

## Deployment Scenarios

### Scenario 1: Default Full Stack (Recommended for New Users)

**Services**: Web + BFF + Akashic + LDAP + PostgreSQL + Redis + (Optional: Loki/Grafana)

```bash
# .env configuration
AKASHIC_USE_BUNDLED_LDAP=true
AKASHIC_USE_BUNDLED_BFF=true
AKASHIC_USE_BUNDLED_WEB=true
AKASHIC_ENABLE_OBSERVABILITY=false
```

**Deployment**:
```bash
git clone https://github.com/your-org/akashic.git
cd akashic
docker-compose up -d
```

**Network Flow**:
```
User → Web (3000) → BFF → Akashic Control (8081, mTLS)
User → Web (3000) → Akashic Auth (8080)
Akashic → LDAP (389/636)
```

**Use Case**: Development, testing, proof-of-concept

---

### Scenario 2: BYOLDAP (Bring Your Own LDAP)

**Services**: Web + BFF + Akashic + External LDAP + PostgreSQL + Redis

```bash
# .env configuration
AKASHIC_USE_BUNDLED_LDAP=false
AKASHIC_EXTERNAL_LDAP_HOST=ldap.company.com
AKASHIC_EXTERNAL_LDAP_PORT=636
```

```yaml
# config.yaml
ldap:
  host: ${AKASHIC_EXTERNAL_LDAP_HOST}
  port: ${AKASHIC_EXTERNAL_LDAP_PORT}
  use_tls: true
  tls_skip_verify: false
  tls_ca_file: ""  # Uses system CA pool for public CAs
```

**Deployment**:
```bash
git clone https://github.com/your-org/akashic.git
cd akashic
# Edit .env and config.yaml
docker-compose up -d
```

**Use Case**: Integration with existing corporate LDAP (Active Directory, FreeIPA, etc.)

---

### Scenario 3: BYOBFF (Bring Your Own BFF)

**Services**: Web + Akashic + LDAP + PostgreSQL + Redis + External BFF

```bash
# .env configuration
AKASHIC_USE_BUNDLED_BFF=false
AKASHIC_CONTROL_SERVER_EXTERNAL_ACCESS=true
```

**Important**: Control server must be accessible to external BFF. Configure firewall/network accordingly.

**External BFF Requirements**:
- Must have client certificate signed by Akashic CA
- Must communicate via mTLS on Control Server port (default: 8081)
- Must implement BFF-Akashic API contract

**Certificate Setup for External BFF**:
```bash
# Generate client certificate for BFF
./build/akashic pki generate-client --name external-bff --dns bff.company.com

# Copy to BFF server
scp certs/clients/external-bff.crt bff-server:/path/to/bff/certs/
scp certs/clients/external-bff.key bff-server:/path/to/bff/certs/
scp certs/ca/ca.crt bff-server:/path/to/bff/certs/
```

**Use Case**: Custom BFF implementation, existing backend infrastructure

---

### Scenario 4: BYOWeb (Bring Your Own Web Frontend)

**Services**: Akashic + BFF + LDAP + PostgreSQL + Redis + External Web

```bash
# .env configuration
AKASHIC_USE_BUNDLED_WEB=false
AKASHIC_CORS_ALLOWED_ORIGINS=https://web.company.com
```

```yaml
# config.yaml
middleware:
  auth:
    cors:
      enabled: true
      allowed_origins:
        - "https://web.company.com"
      allowed_methods: ["GET", "POST", "OPTIONS"]
      allow_credentials: true
```

**External Web Requirements**:
- Must implement OAuth 2.1 / OIDC client flow
- Must follow Akashic API contract for authentication endpoints

**Use Case**: Custom web frontend (React, Vue, Angular, etc.)

---

### Scenario 5: SPA Mode (No BFF)

**Services**: Akashic + LDAP + PostgreSQL + Redis + Web (SPA)

```bash
# .env configuration
AKASHIC_USE_BUNDLED_BFF=false
AKASHIC_SPA_MODE=true
```

**Network Flow**:
```
User → Web (SPA) → Akashic Auth (8080) directly
```

**Important**:
- Control server NOT accessible from web
- Administration via CLI only
- Suitable for public-facing applications without admin UI

**Use Case**: Public-facing SSO, mobile app backends

---

### Scenario 6: Minimal API-Only Mode

**Services**: Akashic + PostgreSQL + Redis

```bash
# .env configuration
AKASHIC_USE_BUNDLED_LDAP=false
AKASHIC_USE_BUNDLED_BFF=false
AKASHIC_USE_BUNDLED_WEB=false
AKASHIC_EXTERNAL_LDAP_HOST=ldap.company.com
```

**Network Flow**:
```
External Systems → Akashic Auth (8080) via OAuth/OIDC
CLI → Akashic Control (8081) via mTLS
```

**Use Case**: API-only integration, headless SSO, service-to-service authentication

---

### Scenario 7: Full Stack with Observability

**Services**: Web + BFF + Akashic + LDAP + PostgreSQL + Redis + Loki + Grafana

```bash
# .env configuration
AKASHIC_ENABLE_OBSERVABILITY=true
```

**Deployment**:
```bash
docker-compose --profile obs up -d
```

**Access**:
- Grafana Dashboard: `http://localhost:3000`
- Loki API: `http://localhost:3100`

**Use Case**: Production monitoring, troubleshooting, compliance logging

---

## Certificate Management

### Certificate Structure

```
certs/
├── ca/
│   ├── ca.crt              # Root CA certificate
│   └── ca.key              # Root CA private key
├── servers/
│   ├── control.crt         # Control server certificate
│   ├── control.key         # Control server private key
│   ├── auth.crt            # Auth server certificate
│   ├── auth.key            # Auth server private key
│   ├── ldap.crt            # LDAP server certificate (if bundled)
│   └── ldap.key            # LDAP server private key (if bundled)
├── clients/
│   ├── cli.crt             # CLI client certificate
│   ├── cli.key             # CLI client private key
│   ├── bff.crt             # BFF client certificate
│   └── bff.key             # BFF client private key
└── compat/                 # Compatibility layer for 3rd party apps
    ├── ldap/
    │   ├── ldap.crt        # Symlink/copy to servers/ldap.crt
    │   ├── ldap.key        # Symlink/copy to servers/ldap.key
    │   └── ca.crt          # Symlink/copy to ca/ca.crt
    └── phpldapadmin/
        └── ca.crt          # Symlink/copy to ca/ca.crt
```

### Certificate Generation

#### Automatic (Zero-Config)

Certificates are automatically generated during first Docker Compose startup via init container:

```bash
# Init container detects missing certificates and generates them
docker-compose up -d
# ✅ Certificates generated automatically
```

#### Manual (Advanced Users)

```bash
# Build akashic binary
go build -o build/akashic ./cmd/akashic

# Run PKI setup script
./scripts/setup-pki.sh

# Verify certificates
./scripts/setup-pki.sh --verify
```

#### Custom Certificates (BYOC - Bring Your Own Certificates)

Place your certificates in the appropriate directories before starting:

```bash
# CA Certificate
cp your-ca.crt certs/ca/ca.crt
cp your-ca.key certs/ca/ca.key

# Server Certificates
cp control-server.crt certs/servers/control.crt
cp control-server.key certs/servers/control.key

# Client Certificates
cp bff-client.crt certs/clients/bff.crt
cp bff-client.key certs/clients/bff.key

# Start services
docker-compose up -d
```

**Requirements for Custom Certificates**:
- CA must be self-signed or from trusted authority
- Server certificates must include appropriate SANs (Subject Alternative Names)
- Client certificates must be signed by the same CA
- PEM format required

### Certificate Compatibility Layer

Third-party applications (LDAP, phpLDAPadmin) expect flat directory structure. The compatibility layer provides this:

**Automatic Setup** (via init container):
```bash
# Init container creates compatibility directories automatically
certs/compat/ldap/
  ├── ldap.crt → ../../servers/ldap.crt
  ├── ldap.key → ../../servers/ldap.key
  └── ca.crt   → ../../ca/ca.crt
```

**Docker Compose Mount**:
```yaml
ldap:
  volumes:
    - ./certs/compat/ldap:/container/service/slapd/assets/certs:ro
```

### Certificate Lifecycle

#### Validity Periods
- **CA Certificate**: 10 years
- **Server Certificates**: 1 year
- **Client Certificates**: 1 year

#### Renewal Process

```bash
# Check expiration dates
./scripts/setup-pki.sh --expiry

# Regenerate all certificates (preserves CA if exists)
./scripts/setup-pki.sh

# Force regenerate everything (including CA)
./scripts/setup-pki.sh --force

# Restart services to load new certificates
docker-compose restart
```

#### Production Recommendations

1. **Certificate Rotation**:
   - Renew certificates 30 days before expiration
   - Use certificate expiration monitoring (Grafana alerts)
   - Automate renewal with cron jobs

2. **CA Security**:
   - Store CA private key securely (encrypted filesystem, HSM, vault)
   - Limit CA key access to authorized personnel only
   - Never commit CA private key to version control

3. **Certificate Backup**:
   - Backup `certs/` directory regularly
   - Store backups in secure, encrypted storage
   - Test certificate restore procedure

---

## Service Components

### Akashic IDP

**Core Components**:
- **Auth Server**: OAuth 2.1 + OIDC authentication endpoints
- **Control Server**: Administrative API for management
- **Config Manager**: Hot-reload configuration management
- **Log Manager**: Multi-channel logging (app, security, audit)
- **User Manager**: Authentication and user directory integration
- **Policy Manager**: OAuth policy management
- **Key Manager**: JWKS and cryptographic key management

**Databases**:
- **PostgreSQL**: Persistent storage (users, clients, policies)
- **Redis**: Sessions, cache, rate limiting

**Ports**:
- `8080`: Auth Server (public-facing)
- `8081`: Control Server (restricted access)

---

### LDAP Server (Bundled)

**Implementation**: OpenLDAP (osixia/openldap:1.5.0)

**Configuration**:
- **Organization**: Defined by `AKASHIC_LDAP_ORGANISATION`
- **Domain**: Defined by `AKASHIC_LDAP_DOMAIN`
- **Base DN**: Automatically derived (e.g., `dc=akashic,dc=local`)

**Ports**:
- `389`: Plain LDAP
- `636`: LDAPS (LDAP over TLS)

**SSL**: Optional, controlled by `LDAP_TLS` environment variable

---

### BFF (Backend For Frontend)

**Responsibilities**:
- Session management
- Token storage and refresh
- OAuth flow coordination
- Admin API gateway to Control Server

**Requirements**:
- Must implement mTLS client for Control Server access
- Must hold client certificate signed by Akashic CA
- Session storage (Redis recommended)

**BYOBFF Requirements**:
- Implement BFF-Akashic API contract
- Support mTLS client authentication
- Handle token lifecycle (issue, refresh, revoke)

---

### Web Frontend

**Default**: React-based single-page application

**Pages**:
- Login page (username/password, OAuth SSO)
- Registration page
- Client registration (OAuth client management)
- Admin dashboard
- User profile

**BYOW eb Requirements**:
- Implement OAuth 2.1 / OIDC client flow
- Follow Akashic authentication API contract
- Support CORS if needed

---

## Configuration Strategy

### Configuration Files

#### 1. `.env` - Service Toggles and Deployment Options

```bash
# Service Toggles
AKASHIC_USE_BUNDLED_LDAP=true
AKASHIC_USE_BUNDLED_BFF=true
AKASHIC_USE_BUNDLED_WEB=true
AKASHIC_ENABLE_OBSERVABILITY=false

# External Service URLs (when BYOX is enabled)
AKASHIC_EXTERNAL_LDAP_HOST=ldap.company.com
AKASHIC_EXTERNAL_LDAP_PORT=636
AKASHIC_EXTERNAL_BFF_URL=https://bff.company.com

# Database
AKASHIC_DATABASE_POSTGRES_HOST_PORT=5432
AKASHIC_DATABASE_POSTGRES_DB=akashic
AKASHIC_DATABASE_POSTGRES_USERNAME=akashic
AKASHIC_DATABASE_POSTGRES_PASSWORD=secure-password

# Redis
AKASHIC_DATABASE_REDIS_PASSWORD=redis-password
AKASHIC_DATABASE_REDIS_HOST_PORT=6379

# LDAP Admin
AKASHIC_LDAP_ADMIN_PASSWORD=ldap-admin-password
AKASHIC_LDAP_CONFIG_PASSWORD=ldap-config-password

# Observability
AKASHIC_LOKI_API_URL=http://loki:3100
AKASHIC_GF_SECURITY_ADMIN_PASSWORD=grafana-password

# SSL Options
AKASHIC_CONTROL_TLS_ENABLED=true
AKASHIC_AUTH_TLS_ENABLED=false
AKASHIC_LDAP_TLS_ENABLED=false
```

#### 2. `config.yaml` - Detailed Service Configuration

```yaml
server:
  auth:
    host: "0.0.0.0"
    port: 8080
    tls:
      enabled: ${AKASHIC_AUTH_TLS_ENABLED:-false}
      cert_file: "./certs/servers/auth.crt"
      key_file: "./certs/servers/auth.key"

  control:
    host: "127.0.0.1"
    port: 8081
    tls:
      enabled: ${AKASHIC_CONTROL_TLS_ENABLED:-true}
      cert_file: "./certs/servers/control.crt"
      key_file: "./certs/servers/control.key"
      ca_file: "./certs/ca/ca.crt"
      client_auth_required: true

database:
  postgres:
    host: "localhost"
    port: ${AKASHIC_DATABASE_POSTGRES_HOST_PORT}
    database: ${AKASHIC_DATABASE_POSTGRES_DB}
    username: ${AKASHIC_DATABASE_POSTGRES_USERNAME}
    password: ${AKASHIC_DATABASE_POSTGRES_PASSWORD}

  redis:
    host: "localhost"
    port: ${AKASHIC_DATABASE_REDIS_HOST_PORT}
    password: ${AKASHIC_DATABASE_REDIS_PASSWORD}

ldap:
  host: ${AKASHIC_EXTERNAL_LDAP_HOST:-localhost}
  port: ${AKASHIC_EXTERNAL_LDAP_PORT:-389}
  base_dn: "dc=akashic,dc=local"
  bind_dn: "cn=admin,dc=akashic,dc=local"
  bind_password: ${AKASHIC_LDAP_ADMIN_PASSWORD}
  use_tls: ${AKASHIC_LDAP_TLS_ENABLED:-false}
  tls_skip_verify: false
  tls_ca_file: "./certs/ca/ca.crt"
```

### Configuration Priority

1. **Command-line flags** (highest priority)
2. **Environment variables** (via `${VAR}` expansion in YAML)
3. **config.yaml** values
4. **Default values** (defined in code)

### Hot-Reload Configuration

Configuration can be reloaded at runtime:

```bash
# Edit config.yaml
vim configs/config.yaml

# Reload via API
curl -X POST https://localhost:8081/config/reload \
  --cert certs/clients/cli.crt \
  --key certs/clients/cli.key \
  --cacert certs/ca/ca.crt

# Or via CLI
./build/akashic cli config reload
```

**Hot-Reloadable Settings**:
- Logging configuration
- Middleware settings
- Database connection pools
- Session timeouts

**Requires Restart**:
- Server host/port changes
- TLS certificate changes
- Database host/credentials

---

## Appendix

### Quick Start Commands

```bash
# Clone and run (default full stack)
git clone https://github.com/your-org/akashic.git
cd akashic
cp .env.example .env
docker-compose up -d

# With observability
docker-compose --profile obs up -d

# BYOLDAP mode
# Edit .env: AKASHIC_USE_BUNDLED_LDAP=false
# Edit config.yaml: ldap.host, ldap.port
docker-compose up -d

# Check status
curl http://localhost:8081/status

# Create admin account
curl -X POST http://localhost:8081/bootstrap/admin \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"secure-password"}'
```

### Troubleshooting

#### Control Server mTLS Connection Refused

```bash
# Check certificate validity
openssl x509 -in certs/clients/cli.crt -noout -text

# Verify CA chain
openssl verify -CAfile certs/ca/ca.crt certs/clients/cli.crt

# Test with curl
curl -v https://localhost:8081/status \
  --cert certs/clients/cli.crt \
  --key certs/clients/cli.key \
  --cacert certs/ca/ca.crt
```

#### LDAP Connection Failed

```bash
# Test plain LDAP
ldapsearch -x -H ldap://localhost:389 \
  -D "cn=admin,dc=akashic,dc=local" \
  -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
  -b "dc=akashic,dc=local"

# Test LDAPS
ldapsearch -x -H ldaps://localhost:636 \
  -D "cn=admin,dc=akashic,dc=local" \
  -w "$AKASHIC_LDAP_ADMIN_PASSWORD" \
  -b "dc=akashic,dc=local"

# Check Akashic logs
docker-compose logs akashic | grep -i ldap
```

#### Certificate Expiration

```bash
# Check all certificates
./scripts/setup-pki.sh --expiry

# Renew certificates
./scripts/setup-pki.sh

# Restart services
docker-compose restart
```

### Security Best Practices

1. **Always enable TLS in production**
2. **Use strong passwords** (min 16 chars, alphanumeric + special)
3. **Rotate certificates** before expiration
4. **Limit Control Server access** (localhost or VPN only)
5. **Enable audit logging** for compliance
6. **Regular security updates** (Docker images, dependencies)
7. **Network segmentation** (isolate databases, LDAP)
8. **Backup encryption keys** and certificates securely

---

**End of Document**
