# Configuration Manager

The configuration management system for Akashic provides runtime configuration management with hot-reload capabilities, validation, and environment-based overrides.

## Features

- **Hot Reload**: Automatically reload configuration when files change
- **Environment Variables**: Override configuration with environment variables
- **Validation**: Essential configuration validation for development phase
- **Multi-format**: Support for YAML and JSON configuration files
- **Change Listeners**: Register callbacks for configuration changes
- **Default Values**: Sensible defaults for logging, database, and session configuration
- **Environment-specific Configs**: Load different configs for dev/staging/production

## Configuration Scope

**Current Phase**: Essential configurations only
- Server settings (API endpoints)
- Database connections (PostgreSQL, Redis)
- Session management
- Basic deployment settings

**Future Phases**: Advanced configurations saved for later implementation
- OAuth 2.1 and OIDC settings
- Security policies and mTLS
- Key management and rotation
- Authentication methods (LDAP, Kerberos)
- Client management
- Guardian protection features

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "akashic/akashic/pkg/config"
)

func main() {
    // Create config manager
    manager, err := config.NewManager("./config.yaml")
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()

    // Get current configuration
    cfg := manager.GetConfig()

    // Use configuration values
    host := cfg.Server.API.Host.GetOrDefault()
    port := cfg.Server.API.Port.GetOrDefault()

    log.Printf("Server will start on %s:%d", host, port)
}
```

### With Options

```go
manager, err := config.NewManager(
    "./config.yaml",
    config.WithLogger(logger),
    config.WithEnvironment("production"),
    config.WithHotReload(true),
)
```

### Using the Loader

```go
loader := config.NewLoader(config.LoaderOptions{
    ConfigPaths:     []string{"./config.yaml", "/etc/akashic/config.yaml"},
    Environment:     "production",
    OverrideFromEnv: true,
    RequireFile:     false,
})

cfg, err := loader.Load()
if err != nil {
    log.Fatal(err)
}
```

## Configuration Structure

### Core Sections

1. **Server**: API and control plane server settings
2. **Security**: mTLS, CORS, and security policies
3. **Database**: PostgreSQL and Redis connection settings
4. **OAuth**: OAuth 2.1 and OIDC configuration
5. **Keys**: Signing and encryption key management
6. **Authentication**: Local, LDAP, Kerberos authentication
7. **Session**: Session and consent management
8. **Tenants**: Multi-tenant configuration
9. **Guardian**: Rate limiting and attack protection
10. **Deployment**: Environment and component settings

### Example Configuration

```yaml
server:
  api:
    host: "0.0.0.0"
    port: 8080
    timeout_read: "30s"
    timeout_write: "30s"
    timeout_idle: "120s"

database:
  postgres:
    host: "localhost"
    port: 5432
    database: "akashic"
    username: "akashic_user"
    password: "${POSTGRES_PASSWORD}"
    ssl_mode: "require"
    max_connections: 100
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"
    db: 0
    pool_size: 10

session:
  timeout: "30m"
  secure_cookies: true
  same_site: "Strict"
  cookie_name: "akashic_session"

deployment:
  environment: "development"  # development, staging, production
  debug: true
  log_level: "info"
```

## Environment Variables

Override any configuration value using environment variables:

```bash
# Server configuration
AKASHIC_SERVER_API_HOST=0.0.0.0
AKASHIC_SERVER_API_PORT=8080
AKASHIC_SERVER_CONTROL_HOST=127.0.0.1
AKASHIC_SERVER_CONTROL_PORT=8081

# Database configuration
AKASHIC_DB_POSTGRES_HOST=localhost
AKASHIC_DB_POSTGRES_PORT=5432
AKASHIC_DB_POSTGRES_DATABASE=akashic
AKASHIC_DB_POSTGRES_USERNAME=akashic_user
AKASHIC_DB_POSTGRES_PASSWORD=secretpassword

AKASHIC_DB_REDIS_HOST=localhost
AKASHIC_DB_REDIS_PORT=6379
AKASHIC_DB_REDIS_PASSWORD=redispassword

# OAuth configuration
AKASHIC_OAUTH_ISSUER=https://akashic.example.com

# Security configuration
AKASHIC_TLS_CA_CERT=./certs/ca.crt
AKASHIC_TLS_SERVER_CERT=./certs/server.crt
AKASHIC_TLS_SERVER_KEY=./certs/server.key
AKASHIC_TLS_CLIENT_CERT=./certs/client.crt
AKASHIC_TLS_CLIENT_KEY=./certs/client.key

# Deployment configuration
AKASHIC_DEPLOYMENT_MODE=production
AKASHIC_DEPLOYMENT_ENVIRONMENT=production
AKASHIC_DEBUG=false
AKASHIC_LOG_LEVEL=info

# Component toggles
AKASHIC_BFF_ENABLED=true
AKASHIC_FRONTEND_ENABLED=true
AKASHIC_CONTROL_PLANE_EXTERNAL=true
AKASHIC_OBSERVABILITY_ENABLED=true
```

## Runtime Configuration Updates

```go
// Register change listener
manager.AddListener("component", func(event config.ChangeEvent) error {
    log.Printf("Config changed: %s.%s", event.Component, event.Key)
    return nil
})

// Update configuration
updates := map[string]interface{}{
    "server.api.port": 9090,
    "server.api.host": "127.0.0.1",
}

err := manager.UpdateConfig(updates)
if err != nil {
    log.Printf("Failed to update config: %v", err)
}
```

## Configuration Validation

The system provides comprehensive validation:

```go
// Validate current configuration
if err := manager.ValidateConfiguration(); err != nil {
    log.Printf("Validation errors: %v", err)
}
```

### Validation Rules

- **Required fields**: Server host/port, database connection details
- **OAuth 2.1 compliance**: PKCE required, implicit flow disabled
- **Security**: Certificate paths exist, valid URLs
- **Network**: Valid IP addresses, port ranges
- **Limits**: Reasonable defaults for connection pools, timeouts

## Deployment Modes

### Minimal Mode
- Akashic IDP only
- Control plane on loopback
- CLI access only

### Recommended Mode (Default)
- Akashic IDP + BFF
- External control plane
- Web and CLI access

### Advanced Mode
- Akashic IDP only
- External control plane
- BYO BFF and Frontend

## File Locations

The loader searches for configuration files in this order:

1. `./config.yaml`
2. `./config.yml`
3. `./configs/config.yaml`
4. `./configs/config.yml`
5. `/etc/akashic/config.yaml`
6. `/etc/akashic/config.yml`

Environment-specific configs:
- `./configs/config.development.yaml`
- `./configs/config.staging.yaml`
- `./configs/config.production.yaml`

## Generating Example Config

```go
err := config.GenerateExampleConfig("./config.example.yaml")
if err != nil {
    log.Fatal(err)
}
```

## Configuration Types

All configuration uses nullable types for optional values:

```go
// Required values
config.Server.API.Host = config.SetRequired("0.0.0.0")

// Optional values
config.Server.API.TimeoutRead = config.SetOptional(30 * time.Second)

// Get values with defaults
host := config.Server.API.Host.GetOrDefault()          // Returns required value
timeout := config.Server.API.TimeoutRead.GetOrDefault() // Returns value or zero
```

## Error Handling

The configuration system provides detailed error information:

```go
type ValidationError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
    Value   string `json:"value,omitempty"`
}
```

Common error scenarios:
- Missing required configuration files
- Invalid YAML/JSON syntax
- Validation failures (invalid URLs, ports, etc.)
- Missing certificate files when mTLS is required
- Environment variable expansion failures

## Best Practices

1. **Use environment variables** for secrets and environment-specific values
2. **Enable hot reload** in development, disable in production
3. **Validate configuration** on startup
4. **Use change listeners** sparingly (only for critical reconfigurations)
5. **Keep default values sensible** for development environments
6. **Document custom configuration** in your application