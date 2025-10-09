# Akashic - Enterprise Identity Provider

**Service Registration-based SSO with OAuth 2.1 + OIDC + LDAP Integration**

Akashic is a production-ready Identity Provider (IDP) service that enables services to implement Single Sign-On (SSO) authentication. It provides a complete authentication infrastructure with support for OAuth 2.1, OIDC, and LDAP-based user management.

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Administration](#administration)
- [Development](#development)
- [Technical Specifications](#technical-specifications)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

## Overview

### What is Akashic?

Akashic serves as an Identity Provider that allows services (called "Tenants") to register and leverage SSO capabilities without implementing their own authentication system. Each Tenant can then allow other services (called "Clients") to integrate with their Akashic instance for OAuth-based authentication.

### Core Components

The Akashic ecosystem consists of three fundamental components:

1. **Frontend** (Optional/BYO)
   - Registration and login pages
   - Admin dashboard
   - Client management interface
   - Customizable to match your brand

2. **Backend For Frontend (BFF)** (Optional/BYO)
   - REST API bridge between frontend and Akashic IDP
   - Session and token management
   - mTLS communication with Akashic
   - HTTPS communication with frontend in production

3. **Akashic IDP** (Core - This Project)
   - OAuth 2.1 and OIDC authentication
   - LDAP/Kerberos integration
   - User and client management
   - Policy and configuration management
   - Dual-server architecture (Auth + Control planes)

### Deployment Modes

1. **Minimal Mode**: IDP only, CLI control via localhost
2. **Recommended Mode**: IDP + default BFF, web + CLI control
3. **Advanced Mode**: IDP + custom BFF + custom frontend

---

## Key Features

### ✅ Implemented Features

#### 🔐 Authentication & Authorization

- **LDAP Integration**
  - Native LDAP client with TLS/LDAPS support
  - User authentication via LDAP bind
  - Directory structure auto-initialization
  - User and group management

- **RBAC (Role-Based Access Control)**
  - Group-based role determination (root/admin/user)
  - Priority-based role resolution (root > admin > user)
  - Configurable LDAP group mappings
  - Default role assignment for unmatched users

- **JIT (Just-In-Time) Provisioning**
  - Automatic user creation on first login
  - LDAP-to-PostgreSQL synchronization
  - RBAC group membership detection
  - Seamless user onboarding

- **Reverse JIT Provisioning**
  - Auto-provision root users from LDAP to database
  - Bootstrap status synchronization
  - Background reconciliation

#### 🔄 User Lifecycle Management

- **Deprovisioning Service**
  - Background reconciliation between LDAP and PostgreSQL
  - Differential deletion thresholds by user type:
    - Root users: **0s** (immediate deletion)
    - Admin users: **30 days**
    - Regular users: **90 days**
  - Missing identity tracking and restoration
  - Automatic bootstrap reset on root user deletion

- **Bootstrap System**
  - Secure initial root user creation
  - Cryptographically secure one-time tokens
  - Token expiration (configurable TTL, default: 1h)
  - CLI and web-based bootstrap support
  - Bootstrap status persistence

#### 🌐 Dual-Server Architecture

- **Auth Server** (Port 8080)
  - Public-facing OAuth/OIDC endpoints
  - User authentication
  - Token issuance (planned)
  - Graceful shutdown support

- **Control Server** (Port 8081)
  - Localhost-only management plane
  - Dynamic auth server control (start/stop/restart)
  - Configuration hot-reload
  - Bootstrap endpoints
  - System status monitoring

#### ⚙️ Configuration Management

- **Hot-Reload Configuration**
  - Runtime configuration updates via API
  - No server restart required
  - Automatic logger reconfiguration
  - Environment variable expansion (`${AKASHIC_*}`)
  - Multi-source configuration (file, env, flags)

- **Configuration Search Paths**
  - Current directory
  - `./configs/`
  - `~/.akashic/`
  - `/etc/akashic/`

#### 📊 Advanced Logging System

- **Multi-Channel Logging**
  - **App Channel**: Application-level logs
  - **Security Channel**: Security events and authentication
  - **Audit Channel**: Compliance and audit trails

- **Multi-Sink Support**
  - stdout/stderr output
  - File logging (append/truncate/rolling)
  - Grafana Loki integration with batching
  - Configurable log levels per channel/sink

- **Loki Integration**
  - Batched log shipping
  - Circuit breaker for resilience
  - GZIP compression
  - Basic auth support
  - Custom labels

#### 🛡️ Middleware System

- **Pre-built Middleware Chains**
  - Request ID injection (UUID)
  - Structured HTTP logging
  - Panic recovery with stack traces
  - Security headers (HSTS, CSP, X-Frame-Options)
  - CORS with configurable origins
  - Request body size limits
  - Token bucket rate limiting
  - Request timeouts
  - IP allowlist (CIDR support)
  - mTLS certificate validation

#### 💾 Data Persistence

- **PostgreSQL Integration**
  - GORM v2 ORM
  - Auto-migration support
  - Connection pooling
  - User and bootstrap status management

- **Redis Integration**
  - Session storage (planned)
  - Bootstrap token storage with TTL
  - Connection pooling
  - Cache support

#### 🖥️ CLI Administration

- **akashic-cli Tool**
  - Bootstrap management (`bootstrap status`, `create-root`)
  - User management (create/list/disable/enable)
  - Server control (start/stop/restart)
  - Configuration management (view/reload)
  - Version information

---

## Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Frontend (Optional)                      │
│                    (Web UI - Default or BYO)                     │
└───────────────────────────────┬─────────────────────────────────┘
                                │ HTTPS (Production)
                                │ HTTP (Development)
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      BFF - Backend For Frontend                  │
│                         (Optional/BYO)                           │
│  • REST API bridge           • Session management               │
│  • Token storage             • mTLS with Akashic                │
└───────────────────────────────┬─────────────────────────────────┘
                                │ mTLS (Client Cert)
                                │
                ┌───────────────┴──────────────┐
                │                              │
                ▼                              ▼
┌──────────────────────────┐   ┌──────────────────────────┐
│   Control Server         │   │    Auth Server           │
│   (127.0.0.1:8081)      │   │    (0.0.0.0:8080)       │
│                          │   │                          │
│ • Server management      │   │ • OAuth 2.1 endpoints    │
│ • Config hot-reload      │   │ • OIDC endpoints         │
│ • Bootstrap endpoints    │   │ • User authentication    │
│ • Status monitoring      │   │ • Token issuance         │
└────────────┬─────────────┘   └────────┬─────────────────┘
             │                          │
             └──────────┬───────────────┘
                        │
        ┌───────────────┼───────────────┬─────────────────┐
        │               │               │                 │
        ▼               ▼               ▼                 ▼
┌──────────────┐ ┌──────────┐ ┌──────────────┐ ┌────────────────┐
│ PostgreSQL   │ │  Redis   │ │     LDAP     │ │ Loki (Optional)│
│              │ │          │ │              │ │                │
│ • Users      │ │ • Tokens │ │ • Users      │ │ • Logs         │
│ • Bootstrap  │ │ • Sessions│ │ • Groups    │ │                │
│ • Clients    │ │ • Cache  │ │ • RBAC       │ │                │
└──────────────┘ └──────────┘ └──────────────┘ └────────────────┘
```

### Initialization Sequence

1. **Configuration**: Load from file → env vars → CLI flags
2. **Logger**: Initialize multi-channel, multi-sink logger
3. **Databases**: Connect to PostgreSQL and Redis
4. **LDAP**: Connect, test, initialize directory structure
5. **RBAC**: Initialize role-based access control service
6. **Migrations**: Auto-migrate PostgreSQL schema
7. **Repositories**: Initialize data access layers
8. **Bootstrap**: Check and initialize bootstrap system
9. **Deprovisioning**: Initialize and run initial reconciliation
10. **Servers**: Create auth and control server instances
11. **Startup**: Start control server, optionally start auth server

### Application Lifecycle

- **Graceful Shutdown**: LIFO closer pattern ensures proper resource cleanup
- **Signal Handling**: SIGINT/SIGTERM trigger graceful shutdown
- **State Management**: Auth server uses state machine (stopped/starting/running/stopping/error)
- **Error Recovery**: Circuit breakers and retry mechanisms for external dependencies

---

## Technology Stack

### Core Technologies

| Component | Technology | Version/Library |
|-----------|-----------|-----------------|
| **Language** | Go | 1.24.3 |
| **HTTP Server** | net/http | Standard library |
| **CLI Framework** | Cobra | github.com/spf13/cobra |
| **Configuration** | Viper | github.com/spf13/viper |
| **PostgreSQL** | GORM v2 + pgx v5 | gorm.io/gorm, gorm.io/driver/postgres |
| **Redis** | go-redis v9 | github.com/redis/go-redis/v9 |
| **LDAP** | go-ldap v3 | github.com/go-ldap/ldap/v3 |
| **Logging** | Zap | go.uber.org/zap |
| **Password Hashing** | bcrypt | golang.org/x/crypto/bcrypt |
| **UUID** | google/uuid | github.com/google/uuid |
| **YAML** | yaml.v3 | gopkg.in/yaml.v3 |

### External Services

- **PostgreSQL**: Primary persistent storage (users, clients, bootstrap status)
- **Redis**: Token storage, session management, caching
- **LDAP/OpenLDAP**: User directory and authentication
- **Grafana Loki**: Log aggregation (optional)

---

## Project Structure

```
akashic/
├── cmd/
│   ├── akashic/              # Main server application
│   │   └── main.go
│   └── akashic-cli/          # CLI administration tool
│       ├── main.go
│       ├── root.go
│       ├── bootstrap.go      # Bootstrap commands
│       ├── user.go           # User management commands
│       ├── server.go         # Server control commands
│       └── config.go         # Config management commands
│
├── pkg/
│   ├── akashic/              # Application lifecycle
│   │   ├── context.go        # AkashicApp initialization
│   │   └── util.go
│   │
│   ├── akashic-cli/          # CLI client library
│   │   ├── client.go
│   │   └── types.go
│   │
│   ├── auth/                 # Authentication service
│   │   ├── service.go        # Auth service with JIT provisioning
│   │   └── password.go       # Password policies and validation
│   │
│   ├── bootstrap/            # Bootstrap system
│   │   ├── manager.go        # Bootstrap manager
│   │   └── token.go          # Token generation and validation
│   │
│   ├── command/              # Cobra commands
│   │   ├── root.go
│   │   ├── run.go
│   │   └── const.go
│   │
│   ├── common/               # Shared utilities
│   │   ├── nullable_types.go # Immutable nullable wrapper
│   │   ├── breaker.go        # Circuit breaker
│   │   ├── interfaces.go     # Interface definitions
│   │   └── util.go
│   │
│   ├── config/               # Configuration management
│   │   ├── config_manager.go # Hot-reload config manager
│   │   ├── types.go          # Config structs
│   │   ├── defaults.go       # Default values
│   │   └── flags.go          # CLI flags
│   │
│   ├── database/             # Database clients
│   │   ├── akashic_postgres/ # PostgreSQL + GORM
│   │   │   └── postgres.go
│   │   └── akashic_redis/    # Redis client
│   │       └── redis.go
│   │
│   ├── ldap/                 # LDAP integration
│   │   ├── client.go         # LDAP client
│   │   ├── rbac.go           # RBAC service
│   │   └── deprovisioning.go # Deprovisioning service
│   │
│   ├── logging/              # Logging system
│   │   ├── logger.go         # Multi-channel logger
│   │   ├── loki_writer.go    # Loki integration
│   │   ├── rolling_file.go   # Rolling file writer
│   │   ├── file.go           # File sink
│   │   ├── appending_file.go # Append mode
│   │   ├── truncated_file.go # Truncate mode
│   │   └── util.go
│   │
│   ├── middleware/           # HTTP middleware
│   │   ├── builder.go        # Chain builder
│   │   ├── logging.go        # HTTP logging
│   │   ├── recovery.go       # Panic recovery
│   │   ├── cors.go           # CORS
│   │   ├── rate_limit.go     # Rate limiting
│   │   ├── security_headers.go # Security headers
│   │   ├── size_limit.go     # Request size limit
│   │   ├── timeout.go        # Request timeout
│   │   ├── ip_allowlist.go   # IP filtering
│   │   ├── mtls.go           # mTLS validation
│   │   ├── request_id.go     # Request ID injection
│   │   ├── types.go          # Config types
│   │   └── enums.go          # Enumerations
│   │
│   ├── models/               # Domain models
│   │   ├── user.go           # User model
│   │   └── bootstrap.go      # Bootstrap status model
│   │
│   ├── repository/           # Data access layer
│   │   ├── user_repository.go      # User CRUD
│   │   └── bootstrap_repository.go # Bootstrap status
│   │
│   └── server/               # HTTP servers
│       ├── auth/             # Auth server (OAuth/OIDC)
│       │   ├── server.go
│       │   ├── handlers.go
│       │   └── routes.go
│       │
│       ├── control/          # Control server (Management)
│       │   ├── server.go
│       │   ├── handlers.go
│       │   ├── routes.go
│       │   ├── state.go      # State machine
│       │   ├── bootstrap_handlers.go
│       │   └── sanitize.go
│       │
│       └── response/         # Response helpers
│           └── response.go
│
├── configs/
│   └── config.yaml           # Main configuration file
│
├── logs/                     # Log output directory (runtime)
├── build/                    # Compiled binaries
├── tmp/                      # Temporary files and test outputs
├── .env                      # Environment variables
├── .env.example              # Environment variable template
├── CLAUDE.md                 # AI-friendly project documentation
└── README.md                 # This file
```

---

## Getting Started

### Prerequisites

- **Go**: 1.24.3 or later
- **PostgreSQL**: 12 or later
- **Redis**: 6 or later
- **OpenLDAP**: 2.4 or later (or any LDAP-compatible server)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/akashic.git
   cd akashic
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your database credentials and LDAP settings
   ```

3. **Build the server**
   ```bash
   go build -o build/akashic ./cmd/akashic
   ```

4. **Build the CLI** (optional)
   ```bash
   go build -o build/akashic-cli ./cmd/akashic-cli
   ```

### Quick Start

1. **Start the server**
   ```bash
   ./build/akashic run --verbose
   ```

2. **On first run**, you'll see a bootstrap token:
   ```
   =======================================================================
     !! BOOTSTRAP MODE ACTIVE !!
   -----------------------------------------------------------------------
     Bootstrap Token:
       7bd98cb8153f0d1527a5735da4678dbdf2d1893becd9d4df6f1482deb011df48

     Token expires in: 1h0m0s
   =======================================================================
   ```

3. **Create root user** (using CLI):
   ```bash
   ./build/akashic-cli bootstrap create-root \
     --token 7bd98cb8153f0d1527a5735da4678dbdf2d1893becd9d4df6f1482deb011df48 \
     --username admin \
     --email admin@example.com
   # You'll be prompted for password securely
   ```

4. **Access the servers**
   - Control API: `http://localhost:8081`
   - Auth API: `http://localhost:8080`

### PKI Setup (Secure Communication)

Akashic supports TLS and mTLS (mutual TLS) for secure communication. This section shows you how to set up certificates for:
- **Control Server**: TLS/mTLS for management API
- **LDAP Server**: TLS for secure directory access
- **Client Authentication**: mTLS certificates for CLI and BFF

#### Quick Setup (Automated)

Use the PKI setup script to automatically generate all required certificates:

```bash
# 1. Build the akashic binary (required for PKI commands)
go build -o build/akashic ./cmd/akashic

# 2. Run the PKI setup script
chmod +x scripts/setup-pki.sh
./scripts/setup-pki.sh
```

The script will:
- Initialize a self-signed Certificate Authority (CA)
- Generate server certificates (control, auth, ldap)
- Generate client certificates (cli, bff)
- Verify all certificates
- Display certificate inventory and expiration status

**Output:**
```
═══════════════════════════════════════════════
  Akashic PKI Setup Script
═══════════════════════════════════════════════

✓ Found Akashic binary
ℹ Initializing Certificate Authority...
✓ Certificate Authority initialized

ℹ Generating server certificates...
  → Control server certificate
  → Auth server certificate
  → LDAP server certificate
✓ Server certificates generated

ℹ Generating client certificates...
  → CLI client certificate
  → BFF client certificate
✓ Client certificates generated

✓ Control server certificate verified
✓ Auth server certificate verified
✓ LDAP server certificate verified
✓ CLI client certificate verified
✓ BFF client certificate verified

═══════════════════════════════════════════════
  PKI setup complete!
═══════════════════════════════════════════════
```

#### Generated Certificate Structure

After running the script, you'll have:

```
certs/
├── ca/
│   ├── ca.crt              # CA certificate (public)
│   └── ca.key              # CA private key (SECRET)
├── servers/
│   ├── control.crt         # Control server certificate
│   ├── control.key         # Control server private key (SECRET)
│   ├── auth.crt            # Auth server certificate
│   ├── auth.key            # Auth server private key (SECRET)
│   ├── ldap.crt            # LDAP server certificate
│   └── ldap.key            # LDAP server private key (SECRET)
└── clients/
    ├── cli.crt             # CLI client certificate
    ├── cli.key             # CLI client private key (SECRET)
    ├── bff.crt             # BFF client certificate
    └── bff.key             # BFF client private key (SECRET)
```

#### Configuration

The default `configs/config.yaml` is already configured to use these certificate paths:

```yaml
server:
  control:
    tls:
      enabled: true
      cert_file: "./certs/servers/control.crt"
      key_file: "./certs/servers/control.key"
      ca_file: "./certs/ca/ca.crt"
      client_auth_required: true  # mTLS enabled

ldap:
  use_tls: true
  tls_skip_verify: false  # Proper verification with CA
  tls_ca_file: "./certs/ca/ca.crt"
```

No configuration changes needed after running the setup script!

#### Testing the Setup

**Test Control Server mTLS:**

```bash
# This will fail (no client certificate)
curl https://localhost:8081/status

# This will succeed (with client certificate)
curl --cert certs/clients/cli.crt \
     --key certs/clients/cli.key \
     --cacert certs/ca/ca.crt \
     https://localhost:8081/status
```

**Expected Response:**
```json
{
  "success": true,
  "data": {
    "server": "control",
    "status": "running",
    "uptime": "2h34m12s",
    "auth_server_status": "running"
  }
}
```

**Test LDAP TLS Connection:**

The LDAP client will automatically use the CA certificate for server verification when `use_tls: true` and `tls_ca_file` is set.

```bash
# Start the server (LDAP connection is tested on startup)
./build/akashic run --verbose

# Look for these log messages:
# [INFO] loaded LDAP CA certificate for server verification
# [INFO] LDAP connection test successful
```

#### Manual PKI Setup (Advanced)

If you prefer manual control, use the `akashic pki` commands directly:

```bash
# 1. Initialize CA
./build/akashic pki init --certs-dir ./certs

# 2. Generate control server certificate
./build/akashic pki generate-server \
    --certs-dir ./certs \
    --name control \
    --dns localhost \
    --dns control.akashic.local \
    --ip 127.0.0.1

# 3. Generate auth server certificate
./build/akashic pki generate-server \
    --certs-dir ./certs \
    --name auth \
    --dns localhost \
    --dns auth.akashic.local \
    --ip 0.0.0.0

# 4. Generate LDAP server certificate
./build/akashic pki generate-server \
    --certs-dir ./certs \
    --name ldap \
    --dns ldap \
    --dns ldap.akashic.local

# 5. Generate CLI client certificate
./build/akashic pki generate-client \
    --certs-dir ./certs \
    --name cli \
    --common-name "Akashic CLI Client"

# 6. Generate BFF client certificate
./build/akashic pki generate-client \
    --certs-dir ./certs \
    --name bff \
    --common-name "Akashic BFF Client"

# 7. Verify certificates
./build/akashic pki verify \
    --certs-dir ./certs \
    --cert ./certs/servers/control.crt

# 8. List all certificates
./build/akashic pki list --certs-dir ./certs

# 9. Check expiration status
./build/akashic pki check-expiry \
    --certs-dir ./certs \
    --warning-days 60
```

#### PKI Management

**Regenerate all certificates:**
```bash
./scripts/setup-pki.sh --force
```

**Verify existing certificates:**
```bash
./scripts/setup-pki.sh --verify
```

**List certificate inventory:**
```bash
./scripts/setup-pki.sh --list
```

**Check certificate expiration:**
```bash
./scripts/setup-pki.sh --expiry
```

**Use custom paths:**
```bash
./scripts/setup-pki.sh \
    --dir /path/to/certs \
    --bin /path/to/akashic
```

#### Certificate Lifecycle

**Certificate Validity:**
- CA: 10 years
- Server certificates: 1 year
- Client certificates: 1 year

**Renewal:**
Certificates should be renewed before expiration. Use the `--force` flag to regenerate:

```bash
./scripts/setup-pki.sh --force
```

**Monitoring:**
Set up automated monitoring to check certificate expiration:

```bash
# Add to crontab (check weekly)
0 0 * * 0 /path/to/scripts/setup-pki.sh --expiry | mail -s "Akashic Certificate Status" admin@example.com
```

#### Security Notes

1. **Never commit private keys to git**
   - `certs/**/*.key` is already in `.gitignore`
   - Only `.crt` files should be committed (if needed)

2. **File permissions** are automatically set:
   - Private keys: `0400` (read-only by owner)
   - Certificates: `0644` (readable by all)

3. **Development vs Production:**
   - **Development**: Self-signed CA is acceptable
   - **Production**: Consider using Let's Encrypt for public-facing endpoints
   - **Internal mTLS**: Self-signed CA is recommended even in production

#### Troubleshooting

**Problem:** `curl: (60) SSL certificate problem: self signed certificate`
**Solution:** Use `--cacert` flag to specify the CA certificate:
```bash
curl --cacert certs/ca/ca.crt https://localhost:8081/status
```

**Problem:** `curl: (35) error:1401E412:SSL routines:CONNECT_CR_FINISHED:sslv3 alert bad certificate`
**Solution:** Ensure you're providing the client certificate with `--cert` and `--key`:
```bash
curl --cert certs/clients/cli.crt --key certs/clients/cli.key --cacert certs/ca/ca.crt https://localhost:8081/status
```

**Problem:** LDAP connection fails with "certificate verify failed"
**Solution:** Check that `tls_ca_file` is set in `configs/config.yaml`:
```yaml
ldap:
  use_tls: true
  tls_skip_verify: false
  tls_ca_file: "./certs/ca/ca.crt"
```

**Problem:** "failed to bind to 127.0.0.1:8081: address already in use"
**Solution:** Kill existing server processes:
```bash
lsof -ti:8081 | xargs kill -9
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run tests for specific package
go test ./pkg/common

# Run specific test
go test -run TestInitAndGet_Primitives ./pkg/common

# Run with verbose output
go test -v ./...
```

---

## Configuration

### Configuration File Structure

The main configuration file (`configs/config.yaml`) has the following sections:

```yaml
server:
  auth:
    host: "0.0.0.0"
    port: 8080
    tls:
      enabled: false
  control:
    host: "127.0.0.1"
    port: 8081

database:
  postgres:
    host: "${AKASHIC_POSTGRES_HOST}"
    port: ${AKASHIC_POSTGRES_PORT}
    database: "${AKASHIC_POSTGRES_DB}"
    user: "${AKASHIC_POSTGRES_USER}"
    password: "${AKASHIC_POSTGRES_PASSWORD}"
  redis:
    host: "${AKASHIC_REDIS_HOST}"
    port: ${AKASHIC_REDIS_PORT}

ldap:
  host: "${AKASHIC_LDAP_HOST}"
  port: ${AKASHIC_LDAP_PORT}
  bind_dn: "${AKASHIC_LDAP_BIND_DN}"
  bind_password: "${AKASHIC_LDAP_BIND_PASSWORD}"
  base_dn: "${AKASHIC_LDAP_BASE_DN}"
  rbac:
    root_group: "cn=akashic-root,ou=groups,dc=akashic,dc=local"
    admin_group: "cn=akashic-admins,ou=groups,dc=akashic,dc=local"
    user_group: "cn=akashic-users,ou=groups,dc=akashic,dc=local"
    default_type: "user"
  deprovisioning:
    enabled: true
    sync_interval: "1h"
    root_deletion_threshold: "0s"
    admin_deletion_threshold: "720h"  # 30 days
    user_deletion_threshold: "2160h"  # 90 days

logging:
  app:
    level: "info"
    sinks:
      - type: "stdout"
        format: "text"
  security:
    level: "info"
    sinks:
      - type: "file"
        path: "logs/security.log"
        mode: "rolling"
  audit:
    level: "info"
    sinks:
      - type: "file"
        path: "logs/audit.log"
        mode: "append"

bootstrap:
  token_ttl: "1h"
  password:
    min_length: 12
    require_uppercase: true
    require_number: true
    require_special: true

middleware:
  auth_server:
    rate_limit:
      enabled: true
      requests_per_second: 100
    cors:
      enabled: true
      allowed_origins: ["*"]
  control_server:
    ip_allowlist:
      enabled: true
      allowed_cidrs: ["127.0.0.1/32"]
```

### Hot-Reload Configuration

Reload configuration without restarting:

```bash
# Using curl
curl -X POST http://localhost:8081/config/reload

# Using CLI
./build/akashic-cli config reload
```

### Environment Variables

All configuration values support environment variable expansion:

```bash
export AKASHIC_POSTGRES_HOST="localhost"
export AKASHIC_POSTGRES_PORT=5432
export AKASHIC_POSTGRES_DB="akashic"
export AKASHIC_POSTGRES_USER="admin"
export AKASHIC_POSTGRES_PASSWORD="your-secure-password"
```

Reference in YAML with `${AKASHIC_*}` syntax.

---

## Administration

### CLI vs Web-Based Control

| Feature | CLI (akashic-cli) | Web BFF (Planned) |
|---------|-------------------|-------------------|
| **Access Method** | Terminal | Browser |
| **Authentication** | Direct API (localhost) | Session + mTLS |
| **Ideal For** | Automation, scripts, DevOps | Human interaction |
| **Session** | Stateless | Cookie-based |
| **Deployment** | Single binary | Frontend + BFF + IDP |
| **Security** | Localhost-only by default | mTLS with client certs |

### CLI Commands

```bash
# Bootstrap Management
akashic-cli bootstrap status
akashic-cli bootstrap create-root --token <token> --username <user> --email <email>

# Server Control
akashic-cli server status
akashic-cli server start
akashic-cli server stop
akashic-cli server restart

# Configuration
akashic-cli config view
akashic-cli config reload

# User Management (planned)
akashic-cli user create --username <user> --email <email>
akashic-cli user list
akashic-cli user disable --id <user-id>
akashic-cli user enable --id <user-id>

# Version
akashic-cli version
```

### Control API Endpoints

```bash
# Server Status
GET /status

# Server Control
POST /server/quit  # Graceful shutdown

# Auth Server Control
POST /auth/start
POST /auth/stop
POST /auth/restart
GET /auth/status

# Configuration
GET /config
POST /config/reload

# Bootstrap
GET /bootstrap/status
POST /bootstrap/create-root
```

---

## Development

### Building

```bash
# Build server
go build -o build/akashic ./cmd/akashic

# Build CLI
go build -o build/akashic-cli ./cmd/akashic-cli

# Build for testing
go build -o build/akashic-test ./cmd/akashic
```

### Running in Development

```bash
# Run with verbose logging
go run ./cmd/akashic run --verbose

# Run with custom config
go run ./cmd/akashic run --config configs/config.yaml --verbose

# Run without auto-starting auth server
go run ./cmd/akashic run --no-auto-start

# Override auth server host/port
go run ./cmd/akashic run --host 0.0.0.0 --port 9090
```

### Code Organization Principles

1. **Interface-Based Dependencies**: Avoids cyclic dependencies
2. **LIFO Closer Pattern**: Ensures proper resource cleanup
3. **Pre-Bind Listener Pattern**: Immediate port conflict detection
4. **State Machine Pattern**: Prevents invalid operations
5. **Middleware Chain Pattern**: Composable request processing
6. **Repository Pattern**: Data access abstraction
7. **Immutable Nullable Types**: Value receivers for safety

---

## Technical Specifications

### JIT Provisioning (Just-In-Time)

**Trigger**: User login

**Process**:
1. User authenticates successfully against LDAP
2. System checks if user exists in PostgreSQL by LDAP DN
3. If not found:
   - Query LDAP group memberships
   - Determine user type via RBAC service (root/admin/user)
   - Create user record in PostgreSQL
   - Link to LDAP DN
4. Return authenticated user

**Use Case**: Users exist in LDAP but not yet in Akashic database

### Reverse JIT Provisioning (Root Users Only)

**Trigger**: Deprovisioning service reconciliation

**Process**:
1. Fetch all users from LDAP
2. Fetch all users from PostgreSQL
3. Find LDAP users not in PostgreSQL
4. For each missing user:
   - Check RBAC group membership
   - If user type is "root":
     - Create user record in PostgreSQL
     - Mark bootstrap as complete
5. Log to audit channel

**Use Case**: Root user managed externally in LDAP, needs to be provisioned to Akashic

### Deprovisioning with Differential Thresholds

**Trigger**: Background service (configurable interval, default: 1h)

**Reconciliation Process**:
1. Fetch all users from LDAP (source of truth)
2. Fetch all users from PostgreSQL
3. For each PostgreSQL user:
   - **If exists in LDAP**:
     - If previously marked as missing → restore identity
   - **If NOT in LDAP**:
     - If not already marked → mark as missing with timestamp
     - If marked and threshold exceeded → delete from PostgreSQL
     - If deleted user was root → reset bootstrap status
4. Run reverse JIT provisioning for root users

**Deletion Thresholds**:
- **Root users**: `0s` (immediate deletion) - Critical security accounts
- **Admin users**: `720h` (30 days) - Administrative accounts
- **Regular users**: `2160h` (90 days) - Standard user accounts

**Rationale**: Different user types have different criticality levels. Root users must be tightly controlled and immediately removed when missing from LDAP. Regular users get grace periods for account recovery.

### RBAC (Role-Based Access Control)

**Mechanism**: LDAP group membership

**Priority Order**: root > admin > user

**Group Mappings**:
- `cn=akashic-root,ou=groups,dc=akashic,dc=local` → root
- `cn=akashic-admins,ou=groups,dc=akashic,dc=local` → admin
- `cn=akashic-users,ou=groups,dc=akashic,dc=local` → user

**Fallback**: Configurable default type (typically "user")

**Process**:
1. Query user's LDAP group memberships
2. Check against RBAC groups in priority order
3. Return first match or default type

### Bootstrap System

**Purpose**: Secure initial root user creation

**Security Features**:
- Cryptographically secure token (32 bytes, hex-encoded)
- One-time use
- TTL-based expiration (default: 1h)
- Double-check prevents race conditions
- Token stored in Redis (automatic expiration)

**Flow**:
1. Server starts, checks PostgreSQL for root user
2. If none exists:
   - Generate secure token
   - Store in Redis with TTL
   - Display token in console
3. Admin submits token + credentials via CLI or web
4. System validates:
   - Token exists and not expired
   - Bootstrap still needed (double-check)
   - Username format valid
   - Email format valid (RFC 5322)
   - Password meets policy requirements
5. Create user in LDAP (password hashed with bcrypt cost 12)
6. Create user in PostgreSQL
7. Assign to root RBAC group
8. Mark bootstrap complete
9. Delete token from Redis
10. Server no longer in bootstrap mode

### Middleware Execution Order

**Auth Server** (port 8080):
1. Request ID
2. Logging
3. Recovery
4. Security Headers
5. CORS
6. Size Limit
7. Rate Limiting
8. Timeout
9. → Handler

**Control Server** (port 8081):
1. Request ID
2. Logging
3. Recovery
4. Security Headers
5. IP Allowlist
6. mTLS (planned)
7. CORS
8. Size Limit
9. Rate Limiting
10. Timeout
11. → Handler

---

## Certificate & Key Requirements

### Overview

Akashic uses a comprehensive Public Key Infrastructure (PKI) for securing various communication channels. This section documents all certificates and cryptographic keys required for development and production deployments.

### Certificate Hierarchy

```
Self-Signed CA (Development)
├── Control Server Certificate (Server TLS)
├── CLI Client Certificate (Client mTLS)
├── BFF Client Certificate (Client mTLS)
├── Auth Server Certificate (Server TLS)
└── LDAP Server Certificate (Server TLS/LDAPS)
```

### Required Certificates

#### 🔴 HIGH PRIORITY - Control Plane Security

**1. Self-Signed CA (Certificate Authority)**
- **Purpose**: Root of trust for all internal certificates
- **Type**: X.509 CA certificate
- **Key**: RSA 4096-bit or ECDSA P-384
- **Validity**: 10 years
- **Location**: `certs/ca/ca.crt` + `certs/ca/ca.key`
- **Usage**: Sign all server and client certificates
- **Status**: ⚠️ To be implemented

**2. Control Server Certificate**
- **Purpose**: TLS for control plane management API
- **Type**: Server certificate
- **Endpoint**: `https://127.0.0.1:8081`
- **SANs**: `localhost`, `127.0.0.1`, `::1`
- **Issued by**: Self-signed CA
- **Config**: `server.control.tls.cert_file` in `config.yaml`
- **Status**: ⚠️ Config exists, cert generation needed

**3. CLI Client Certificate**
- **Purpose**: mTLS authentication for `akashic-cli` tool
- **Type**: Client certificate
- **Usage**: Authenticate CLI to control server
- **Issued by**: Self-signed CA
- **Common Name**: `akashic-cli`
- **Middleware**: Already implemented in `pkg/middleware/mtls.go`
- **Status**: ⚠️ Middleware ready, cert generation needed

**4. BFF Client Certificate**
- **Purpose**: mTLS authentication for Backend-For-Frontend service
- **Type**: Client certificate
- **Usage**: Authenticate BFF to control server
- **Issued by**: Self-signed CA
- **Common Name**: `akashic-bff`
- **Status**: ⚠️ To be implemented when BFF is built

#### 🟡 MEDIUM PRIORITY - Public-Facing Services

**5. Auth Server Certificate**
- **Purpose**: HTTPS for OAuth/OIDC endpoints
- **Type**: Server certificate
- **Endpoint**: `https://auth.akashic.local:8080`
- **SANs**: `auth.akashic.local`, additional domains
- **Issued by**: Let's Encrypt (production) or Self-signed CA (dev)
- **Config**: To be added to `config.yaml`
- **Status**: ⚠️ To be implemented

**6. LDAP Server Certificate**
- **Purpose**: Secure LDAP communication (LDAPS)
- **Type**: Server certificate
- **Endpoint**: `ldaps://ldap:636`
- **SANs**: `ldap`, `localhost`
- **Issued by**: Self-signed CA
- **Config**: `ldap.use_tls` in `config.yaml` (already exists)
- **Current**: Uses `tls_skip_verify` - needs proper cert
- **Status**: ⚠️ Config exists, proper cert verification needed

#### 🟢 LOW PRIORITY - Optional Security

**7. BFF Server Certificate**
- **Purpose**: HTTPS for frontend gateway (production)
- **Type**: Server certificate
- **Endpoint**: `https://bff.akashic.local`
- **Issued by**: Let's Encrypt (production) or Self-signed CA (dev)
- **Status**: ⏸️ Deferred until BFF implementation

**8. PostgreSQL TLS** (Optional)
- **Purpose**: Encrypted database connections
- **Type**: Server certificate
- **Usage**: Paranoid security for internal traffic
- **Priority**: Very Low (Docker network is already isolated)
- **Status**: ⏸️ Optional enhancement

**9. Redis TLS** (Optional)
- **Purpose**: Encrypted cache connections
- **Type**: Server certificate
- **Usage**: Paranoid security for internal traffic
- **Priority**: Very Low
- **Status**: ⏸️ Optional enhancement

### Cryptographic Keys (Non-TLS)

#### 🔴 HIGH PRIORITY - OAuth/OIDC

**10. JWT Signing Keys**
- **Purpose**: Sign OAuth access tokens and OIDC ID tokens
- **Algorithm**: RSA 2048/4096 or ECDSA P-256/P-384
- **Format**: JWK (JSON Web Key)
- **Key Rotation**: Supported with versioning (`kid` parameter)
- **Location**: `keys/jwt/`
- **Exposed via**: `/.well-known/jwks.json` endpoint
- **Status**: ⚠️ To be implemented (roadmap item)

**11. JWT Encryption Keys** (Optional)
- **Purpose**: Encrypt sensitive tokens (JWE - JSON Web Encryption)
- **Algorithm**: RSA-OAEP or ECDH-ES
- **Usage**: For highly sensitive claims
- **Status**: ⏸️ Optional feature

#### 🟡 MEDIUM PRIORITY - Data Protection

**12. Token Encryption Key**
- **Purpose**: Encrypt refresh tokens and session data at rest
- **Algorithm**: AES-256-GCM
- **Storage**: Encrypted in Redis/PostgreSQL
- **Key Management**: Application-level encryption
- **Status**: ⚠️ To be implemented

**13. Client Secret Encryption**
- **Purpose**: Encrypt OAuth client secrets in database
- **Algorithm**: AES-256-GCM
- **Usage**: Prevent plaintext secret storage
- **Status**: ⚠️ To be implemented

### Development vs Production Strategy

#### Development Mode (Current)

```yaml
Strategy: Self-Signed CA for all certificates
├── Fast setup and iteration
├── No external dependencies
├── Full mTLS and TLS support
└── Use tls_skip_verify only for testing
```

**Setup:**
```bash
# Initialize PKI (creates self-signed CA)
akashic-cli pki init

# Generate control server certificate
akashic-cli pki generate-server --name control-server

# Generate CLI client certificate
akashic-cli pki generate-client --name cli

# Generate LDAP server certificate
akashic-cli pki generate-server --name ldap --san ldap,localhost
```

#### Production Mode (Future)

```yaml
Strategy: Let's Encrypt + Self-Signed CA hybrid
├── Let's Encrypt for public endpoints (Auth Server, BFF)
├── Self-Signed CA for internal mTLS (Control Plane)
├── Certificate auto-renewal
└── Proper certificate monitoring
```

**Public Certs (Let's Encrypt):**
- Auth Server: Auto-renewed via ACME protocol
- BFF Server: Auto-renewed via ACME protocol

**Internal Certs (Self-Signed CA):**
- Control Server: Manual renewal (long validity)
- mTLS Client Certs: Manual issuance per client
- LDAP Server: Manual renewal

### Certificate Management

#### Locations

```
certs/
├── ca/
│   ├── ca.crt              # CA certificate (public)
│   └── ca.key              # CA private key (⚠️ SECRET)
├── server/
│   ├── control.crt         # Control server cert
│   ├── control.key         # Control server key (⚠️ SECRET)
│   ├── auth.crt            # Auth server cert
│   ├── auth.key            # Auth server key (⚠️ SECRET)
│   ├── ldap.crt            # LDAP server cert
│   └── ldap.key            # LDAP server key (⚠️ SECRET)
└── client/
    ├── cli.crt             # CLI client cert
    ├── cli.key             # CLI client key (⚠️ SECRET)
    ├── bff.crt             # BFF client cert
    └── bff.key             # BFF client key (⚠️ SECRET)

keys/
└── jwt/
    ├── signing.pem         # JWT signing key (⚠️ SECRET)
    └── signing.pub         # JWT public key (JWKS)
```

#### Validity Periods

| Certificate Type | Development | Production |
|-----------------|-------------|------------|
| Self-Signed CA | 10 years | N/A |
| Server Certs | 1 year | 90 days (Let's Encrypt) |
| Client Certs | 1 year | 1 year |
| JWT Signing Keys | No expiry | Rotate every 6 months |

#### Security Best Practices

1. **Never commit private keys to git**
   - Add `certs/**/*.key` to `.gitignore`
   - Add `keys/**/*.pem` to `.gitignore`
   - Only commit `.crt` (public) files

2. **Use proper file permissions**
   - CA key: `0400` (read-only for owner)
   - Server keys: `0400`
   - Client keys: `0400`
   - Public certs: `0644`

3. **Regular rotation**
   - Rotate JWT signing keys every 6 months
   - Renew server certificates before expiry
   - Monitor certificate expiration

4. **Secure storage in production**
   - Use hardware security modules (HSM) for CA key
   - Use secrets management (HashiCorp Vault, AWS Secrets Manager)
   - Encrypt keys at rest

### PKI Package

Akashic includes a comprehensive PKI package (`pkg/pki/`) for certificate management:

**Features:**
- Self-signed CA generation
- Server certificate generation with SANs
- Client certificate generation for mTLS
- Certificate validation and verification
- PEM encoding/decoding
- Key generation (RSA 2048/4096, ECDSA P-256/P-384)

**CLI Commands:**
```bash
# Initialize PKI with self-signed CA
akashic-cli pki init

# Generate server certificate
akashic-cli pki generate-server --name <name> --san <hostname1,hostname2>

# Generate client certificate
akashic-cli pki generate-client --name <name>

# List certificates
akashic-cli pki list

# Verify certificate
akashic-cli pki verify --cert <path>

# Renew certificate
akashic-cli pki renew --name <name>
```

**Status**: 🚧 Under development

---

## Roadmap

### ✅ Completed (v0.0.2)

- [x] Dual-server architecture (Auth + Control)
- [x] Configuration management with hot-reload
- [x] Multi-channel logging system (App, Security, Audit)
- [x] LDAP integration with TLS support
- [x] RBAC with LDAP groups
- [x] JIT provisioning
- [x] Reverse JIT provisioning (root users)
- [x] Deprovisioning service with differential thresholds
- [x] Bootstrap system with secure tokens
- [x] PostgreSQL integration with GORM
- [x] Redis integration
- [x] Middleware system (10 middleware types)
- [x] CLI administration tool
- [x] Graceful shutdown with LIFO closers
- [x] Loki log integration
- [x] Password policies and validation
- [x] User repository pattern
- [x] State machine for auth server lifecycle

### 🚧 In Progress

- [ ] OAuth 2.1 authorization code flow
- [ ] OIDC core implementation
- [ ] Token endpoints (access, refresh, introspection, revocation)
- [ ] Client registration API
- [ ] JWKS and key management

### 📋 Planned (v0.1.0)

#### Security & PKI
- [ ] **PKI Package for TLS Management**
  - [ ] Self-signed CA generation
  - [ ] Server certificate generation and rotation
  - [ ] Client certificate generation for mTLS
  - [ ] Certificate revocation lists (CRL)
  - [ ] OCSP responder

- [ ] **mTLS for Control Plane**
  - [ ] Client certificate validation
  - [ ] Certificate-based authentication
  - [ ] mTLS middleware integration

#### OAuth & OIDC
- [ ] **OAuth 2.1 Full Implementation**
  - [ ] Authorization code flow
  - [ ] PKCE (Proof Key for Code Exchange)
  - [ ] Token management (access, refresh)
  - [ ] Scope validation
  - [ ] Consent management

- [ ] **OIDC Implementation**
  - [ ] ID tokens
  - [ ] UserInfo endpoint
  - [ ] Discovery endpoint (.well-known/openid-configuration)
  - [ ] Claims and scopes

- [ ] **Key Manager**
  - [ ] JWKS endpoint
  - [ ] Signing key rotation
  - [ ] Encryption key management
  - [ ] Key versioning

#### User Management
- [ ] **SCIM 2.0 Integration**
  - [ ] User provisioning API
  - [ ] Group management API
  - [ ] Bulk operations
  - [ ] Resource filtering and pagination

- [ ] **Enhanced User Features**
  - [ ] User profile management
  - [ ] Account recovery
  - [ ] Password reset flow
  - [ ] Email verification
  - [ ] MFA (Multi-Factor Authentication)

#### Tenant & Client Management
- [ ] **Policy Manager**
  - [ ] Tenant-specific policies
  - [ ] OAuth policy configuration
  - [ ] Client policies

- [ ] **Client Manager**
  - [ ] Client registration API
  - [ ] Client credentials management
  - [ ] Redirect URI validation
  - [ ] Client secret rotation

#### Session Management
- [ ] **Session Manager**
  - [ ] Redis-backed sessions
  - [ ] SSO session management
  - [ ] Session revocation
  - [ ] Concurrent session limits

- [ ] **Consent Manager**
  - [ ] Consent history tracking
  - [ ] Consent revocation
  - [ ] Scope-based consent

#### Frontend & BFF
- [ ] **Default Frontend**
  - [ ] Login page
  - [ ] Registration page
  - [ ] Consent page
  - [ ] Admin dashboard
  - [ ] Client management UI

- [ ] **Backend For Frontend (BFF)**
  - [ ] REST API bridge
  - [ ] Session management
  - [ ] Token storage
  - [ ] mTLS with Akashic

#### Monitoring & Observability
- [ ] **Prometheus Metrics**
  - [ ] Request metrics
  - [ ] Authentication metrics
  - [ ] Token issuance metrics
  - [ ] Error rates

- [ ] **Enhanced Health Checks**
  - [ ] Component-level health (DB, LDAP, Redis)
  - [ ] Dependency health
  - [ ] Readiness vs liveness

#### Deployment
- [ ] **Docker Compose**
  - [ ] `obs` profile (Loki + Grafana)
  - [ ] `fe` profile (Frontend + BFF)
  - [ ] Default profile (Redis + PostgreSQL + Akashic)

- [ ] **Kubernetes Manifests**
  - [ ] Deployment configs
  - [ ] Service definitions
  - [ ] Ingress rules
  - [ ] ConfigMaps and Secrets

#### Integrations
- [ ] **Kerberos Support**
  - [ ] Kerberos authentication
  - [ ] Ticket validation
  - [ ] Service principal management

- [ ] **External IDP Integration**
  - [ ] SAML support
  - [ ] Social login (Google, GitHub, etc.)
  - [ ] LDAP federation

#### Developer Experience
- [ ] **API Documentation**
  - [ ] OpenAPI/Swagger specs
  - [ ] Postman collections
  - [ ] Integration guides

- [ ] **Testing**
  - [ ] Integration test suite
  - [ ] E2E test suite
  - [ ] Load testing
  - [ ] Security testing (OWASP)

#### Configuration Enhancements
- [ ] **Advanced Config Features**
  - [ ] Configuration versioning
  - [ ] Configuration rollback
  - [ ] Partial updates (PATCH)
  - [ ] Configuration validation hooks

### 🔮 Future Considerations

- [ ] Multi-tenancy support
- [ ] Rate limiting per user/client
- [ ] Webhooks for events
- [ ] Audit log export
- [ ] Compliance features (GDPR, SOC2)
- [ ] High availability setup
- [ ] Database sharding
- [ ] Geographic distribution

---

## Contributing

We welcome contributions! Please see our contributing guidelines (coming soon).

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Write tests
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow Go conventions (`gofmt`, `golint`)
- Write meaningful commit messages
- Add tests for new features
- Update documentation

---

## License

[To be determined]

---

## Support

- **Documentation**: See `CLAUDE.md` for detailed technical documentation
- **Issues**: [GitHub Issues](https://github.com/yourusername/akashic/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/akashic/discussions)

---

## Acknowledgments

Built with:
- [Go](https://golang.org/)
- [GORM](https://gorm.io/)
- [Zap](https://github.com/uber-go/zap)
- [Cobra](https://github.com/spf13/cobra)
- [Viper](https://github.com/spf13/viper)
- And many other excellent open-source projects

---

**Last Updated**: October 2025
**Version**: 0.0.2
**Status**: Active Development
