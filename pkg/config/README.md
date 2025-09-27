# Configuration Package

The configuration management system for Akashic provides runtime configuration management with hot-reload capabilities, validation, and environment-based overrides using Viper and Cobra.

## Overview

This package provides a **simplified configuration system** focused on essential components only for the current development phase:

- **Server Configuration**: Auth server and control plane (mTLS) settings
- **Database Configuration**: PostgreSQL and Redis connections
- **Session Management**: Cookie and session settings
- **Logging Configuration**: Multi-sink logging system integration
- **Deployment Settings**: Environment and debug mode configuration

**Future Expansion**: Advanced OAuth 2.1, OIDC, security policies, and authentication methods will be added in later development phases.

## Architecture

The package uses **Viper** for configuration management to handle complex YAML unmarshaling and provide robust features:

- **ViperManager**: Primary configuration interface with hot-reload and change listeners
- **Nullable Types**: `Required[T]` and `Optional[T]` for type-safe configuration values
- **Environment Variables**: Automatic override with `AKASHIC_` prefix
- **File Watching**: Automatic reload when configuration files change
- **Validation**: Essential configuration validation for startup safety

## Quick Start

### Basic Usage with ViperManager

```go
package main

import (
    "akashic/akashic/pkg/config"
    "akashic/akashic/pkg/logging"
)

func main() {
    // Create logger (optional)
    logger, _ := logging.NewLogger("development", "akashic")

    // Create configuration manager
    manager, err := config.NewViperManager("config",
        config.WithViperLogger(logger),
        config.WithViperEnvironment("development"),
        config.WithViperHotReload(true),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()

    // Get current configuration
    cfg := manager.GetConfig()

    // Use configuration values
    authHost := cfg.Server.Auth.Host.GetOrDefault()
    authPort := cfg.Server.Auth.Port.GetOrDefault()
    controlHost := cfg.Server.Control.Host.GetOrDefault()
    controlPort := cfg.Server.Control.Port.GetOrDefault()

    fmt.Printf("Auth Server: %s:%d\n", authHost, authPort)
    fmt.Printf("Control Server: %s:%d\n", controlHost, controlPort)
}
```

### Using with Cobra CLI

The package integrates with Cobra CLI for configuration display and management:

```bash
# Show current configuration (pretty format)
./akashic --config myconfig --env production

# Show configuration as JSON
./akashic config show --output json

# Validate configuration
./akashic config validate --config myconfig --env production
```

## Configuration Structure

### Current Essential Configuration

```yaml
# Server configuration for API endpoints and control plane
server:
  auth:
    host: "0.0.0.0"          # Auth server host (OAuth/OIDC endpoints)
    port: 8080               # Auth server port
  control:
    host: "127.0.0.1"        # Control server host (mTLS management)
    port: 8081               # Control server port
    tls:
      enabled: true          # Enable TLS for control server
      cert_file: "./certs/server.crt"     # Server certificate
      key_file: "./certs/server.key"      # Server private key
      ca_file: "./certs/ca.crt"           # CA certificate
      client_auth_required: true          # Require client certificates

# Database connections
database:
  postgres:
    host: "localhost"
    port: 5432
    database: "akashic"
    username: "akashic_user"
    password: "${POSTGRES_PASSWORD}"     # Use environment variable
    ssl_mode: "require"
    max_connections: 100
    max_idle_connections: 10
    connection_lifetime: "1h"
  redis:
    host: "localhost"
    port: 6379
    password: "${REDIS_PASSWORD}"        # Use environment variable
    db: 0
    pool_size: 10
    session_ttl: "24h"
    cache_ttl: "1h"

# Session management
session:
  timeout: "30m"
  secure_cookies: true
  same_site: "Strict"                    # Strict, Lax, or None
  cookie_name: "akashic_session"
  cookie_path: "/"

# Logging configuration (integrates with pkg/logging)
logging:
  service_name: "akashic"
  env: "development"

# Deployment settings
deployment:
  environment: "development"             # development, staging, production
  debug: true
```

## Environment Variables

Override any configuration value using environment variables with `AKASHIC_` prefix:

```bash
# Server configuration
export AKASHIC_SERVER_AUTH_HOST=0.0.0.0
export AKASHIC_SERVER_AUTH_PORT=8080
export AKASHIC_SERVER_CONTROL_HOST=127.0.0.1
export AKASHIC_SERVER_CONTROL_PORT=8081

# Database configuration
export AKASHIC_DATABASE_POSTGRES_HOST=localhost
export AKASHIC_DATABASE_POSTGRES_PORT=5432
export AKASHIC_DATABASE_POSTGRES_DATABASE=akashic
export AKASHIC_DATABASE_POSTGRES_USERNAME=akashic_user
export AKASHIC_DATABASE_POSTGRES_PASSWORD=secretpassword

export AKASHIC_DATABASE_REDIS_HOST=localhost
export AKASHIC_DATABASE_REDIS_PORT=6379
export AKASHIC_DATABASE_REDIS_PASSWORD=redispassword

# Session configuration
export AKASHIC_SESSION_TIMEOUT=30m
export AKASHIC_SESSION_SECURE_COOKIES=true

# Deployment configuration
export AKASHIC_DEPLOYMENT_ENVIRONMENT=production
export AKASHIC_DEPLOYMENT_DEBUG=false
```

## Configuration File Locations

Viper searches for configuration files in this order:

1. `./config.yaml` (if name is "config")
2. `./configs/config.yaml`
3. `/etc/akashic/config.yaml`

## Hot Reload and Change Listeners

```go
// Register change listener for configuration updates
manager.AddListener("database", func(event config.ChangeEvent) error {
    log.Printf("Config changed: %s at %s", event.Key, event.Timestamp)
    // Handle configuration change (e.g., reconnect to database)
    return nil
})

// Hot reload is enabled by default in development
manager, err := config.NewViperManager("config",
    config.WithViperHotReload(true),  // Enable hot reload
)
```

## Validation

The system provides essential validation for startup safety:

```go
// Validation is performed automatically during LoadConfig()
// But you can also validate manually:
cfg := manager.GetConfig()
if err := validateViperConfig(cfg); err != nil {
    log.Printf("Validation failed: %v", err)
}
```

### Validation Rules

**Required Fields:**
- Server host and port for both auth and control servers
- Database connection details (host, port, database name, credentials)
- TLS certificate files when TLS is enabled

**Format Validation:**
- Valid IP addresses and hostnames
- Port numbers (1-65535)
- Environment values (development, staging, production)
- SameSite cookie values (Strict, Lax, None)

**File Validation:**
- TLS certificate files must exist when TLS is enabled
- Key files and CA files accessibility

## Nullable Types Pattern

The configuration uses a nullable types pattern for type safety:

```go
// Type definitions
type Optional[T any] = common.Nullable[T]
type Required[T any] = common.Nullable[T]

// Setting values
host := config.SetRequired("0.0.0.0")        // Required value
timeout := config.SetOptional(30 * time.Second)  // Optional value

// Getting values
if value, ok := host.Get(); ok {
    // Value is present
    fmt.Printf("Host: %s", value)
}

// Getting with defaults
hostValue := host.GetOrDefault()              // Returns value or zero value
timeoutValue := timeout.GetOrDefault()        // Returns value or zero value
```

## Error Handling

```go
type ValidationError struct {
    Field   string `json:"field"`
    Message string `json:"message"`
    Value   string `json:"value,omitempty"`
}
```

Common error scenarios:
- Missing required configuration values
- Invalid YAML syntax in configuration files
- Validation failures (invalid ports, missing certificate files)
- Environment variable expansion failures

## Integration with Cobra CLI

The package provides CLI commands for configuration management:

```go
// Root command shows configuration
./akashic --config myconfig --env production --output pretty

// Configuration subcommands
./akashic config show --output json
./akashic config validate
```

**Output Formats:**
- `pretty`: Human-readable format with emojis and sections (default)
- `json`: JSON format for scripting
- `yaml`: YAML format (planned)

## Best Practices

1. **Use environment variables** for secrets (passwords, tokens)
2. **Enable hot reload** in development, consider disabling in production
3. **Validate configuration** on application startup
4. **Use change listeners** sparingly for critical reconfigurations only
5. **Keep certificates** in a secure location with proper permissions
6. **Follow the single-tenant architecture** - one Akashic instance per organization

## Future Expansion

The configuration system is designed for future expansion. Planned additions include:

- **OAuth 2.1 & OIDC Configuration**: Authorization flows, token settings, PKCE requirements
- **Security Policies**: Rate limiting, CORS, content security policies
- **Authentication Methods**: LDAP, Kerberos, multi-factor authentication
- **Client Management**: 3rd party service registration and management
- **Advanced TLS**: Certificate rotation, ACME integration
- **Observability**: Metrics, tracing, and monitoring configuration

The current simplified structure ensures we can add these features incrementally without breaking existing functionality.