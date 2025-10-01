# Configuration Package

The configuration management system for Akashic provides robust configuration management with environment variable expansion, type-safe parsing, and extensible architecture using Viper and Cobra.

## Overview

This package provides a **production-ready configuration system** focused on essential components for OAuth 2.1/OIDC server functionality:

- **Server Configuration**: Auth server and control plane (mTLS) settings
- **Database Configuration**: PostgreSQL and Redis connections with environment variable support
- **Session Management**: Cookie and session security settings
- **Logging Configuration**: Multi-sink logging system with stdout, file, and Loki support
- **Deployment Settings**: Environment-specific configuration management

**Current Status**: Core configuration architecture is complete with safe type assertions, environment variable expansion, and extensible closer function chains.

## Architecture

The package uses **ConfigManager** with Viper for robust configuration handling:

- **ConfigManager**: Primary configuration interface with safe type assertions and verbose printing
- **Interface-Based Design**: Uses `common.VerbosePrinter` interface to avoid cyclic dependencies
- **Environment Variable Expansion**: Automatic `${VAR}` expansion in YAML files with `AKASHIC_` prefix
- **Type Safety**: Safe type assertions with proper nil checking and error handling
- **Graceful Shutdown**: Integration with application lifecycle management
- **Validation**: Comprehensive configuration validation for startup safety

## Quick Start

### Basic Usage with ConfigManager

```go
package main

import (
    "akashic/akashic/pkg/config"
    "akashic/akashic/pkg/logging"
    "github.com/spf13/cobra"
)

// VerbosePrinter implementation for basic usage
type SimpleVerbosePrinter struct {
    verbose bool
}

func (s *SimpleVerbosePrinter) VerbosePrintlnf(format string, args ...interface{}) {
    if s.verbose {
        fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
    }
}

func main() {
    // Create a Cobra command (usually done in CLI setup)
    cmd := &cobra.Command{Use: "example"}
    config.RegisterFlags(cmd)

    // Create verbose printer
    verbosePrinter := &SimpleVerbosePrinter{verbose: true}

    // Create configuration manager
    manager, err := config.NewConfigManager(cmd, verbosePrinter)
    if err != nil {
        log.Fatal(err)
    }

    // Get current configuration
    cfg := manager.GetConfig()

    // Use configuration values
    fmt.Printf("Auth Server: %s:%d\n",
        cfg.Server.Auth.Host, cfg.Server.Auth.Port)
    fmt.Printf("Control Server: %s:%d\n",
        cfg.Server.Control.Host, cfg.Server.Control.Port)
    fmt.Printf("Database: %s@%s:%d/%s\n",
        cfg.Database.Postgres.Username, cfg.Database.Postgres.Host,
        cfg.Database.Postgres.Port, cfg.Database.Postgres.Database)
}
```

### Using with AkashicApp (Recommended)

The most common usage is within the AkashicApp architecture:

```go
app := akashic.NewAkashicApp()
if err := app.Init(cmd, args); err != nil {
    log.Fatal(err)
}
defer app.Close() // Automatically handles ConfigManager cleanup

// Configuration is available through app.Config
cfg := app.Config.GetConfig()
```

### Command Line Usage

```bash
# Run with verbose output
./akashic --verbose

# Use custom configuration file
./akashic --config /path/to/config.yaml --verbose

# Configuration is automatically loaded with environment variable expansion
./akashic --verbose
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

# Database connections with environment variable support
database:
  postgres:
    host: "localhost"
    port: ${AKASHIC_DATABASE_POSTGRES_HOST_PORT}
    database: ${AKASHIC_DATABASE_POSTGRES_DB}
    username: ${AKASHIC_DATABASE_POSTGRES_USERNAME}
    password: ${AKASHIC_DATABASE_POSTGRES_PASSWORD}     # Use environment variable
    ssl_mode: "require"
    max_connections: 100
    max_idle_connections: 10
    connection_lifetime: "1h"
  redis:
    host: "localhost"
    port: 6379
    password: ${AKASHIC_DATABASE_REDIS_PASSWORD}        # Use environment variable
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

# Logging configuration with multiple sink support
logging:
  service_name: "akashic"
  encoder:
    timestamp_key: "timestamp"
    time_format: "Mon Jan _2 15:04:05 MST 2006" # UnixDate
    level_key: "level"
    name_key: "logging"
    caller_key: "caller"
    message_key: "message"
    stacktrace_key: "stacktrace"
  app:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2
    sinks:
      - type: "stdout"       # stdout, stderr, file, loki
        enabled: true
        level: "debug"       # debug, info, warn, error, fatal
        format: "text"       # json, text
      - type: "file"
        enabled: true
        level: "debug"
        format: "text"
        file_path: "./logs/app.log"
        file_mode: "rolling" # append, truncate, rolling
      - type: "loki"
        enabled: true
        level: "debug"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true
  security:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2
    sinks:
      - type: "stdout"
        enabled: true
        level: "debug"
        format: "text"
      - type: "file"
        enabled: true
        level: "debug"
        format: "text"
        file_path: "./logs/security.log"
        file_mode: "append"
      - type: "loki"
        enabled: true
        level: "debug"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true
  audit:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2
    sinks:
      - type: "stdout"
        enabled: true
        level: "debug"
        format: "text"
      - type: "file"
        enabled: true
        level: "debug"
        format: "text"
        file_path: "./logs/audit.log"
        file_mode: "append"
      - type: "loki"
        enabled: true
        level: "debug"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true

# Deployment settings
deployment:
  environment: "development"             # development, staging, production
```

## Environment Variables

Override any configuration value using environment variables with `AKASHIC_` prefix:

```bash
# Server configuration
export AKASHIC_SERVER_AUTH_HOST=0.0.0.0
export AKASHIC_SERVER_AUTH_PORT=8080
export AKASHIC_SERVER_CONTROL_HOST=127.0.0.1
export AKASHIC_SERVER_CONTROL_PORT=8081

# Database configuration (matches current .env structure)
export AKASHIC_DATABASE_POSTGRES_HOST_PORT=5432
export AKASHIC_DATABASE_POSTGRES_DB=akashic
export AKASHIC_DATABASE_POSTGRES_USERNAME=admin
export AKASHIC_DATABASE_POSTGRES_PASSWORD=postgres123

export AKASHIC_DATABASE_REDIS_PASSWORD=redis123
export AKASHIC_DATABASE_REDIS_HOST_PORT=6379

# Logging configuration
export AKASHIC_LOKI_HOST_PORT=3100
export AKASHIC_LOKI_API_URL="http://localhost:3100/loki/api/v1/push"

# Session configuration
export AKASHIC_SESSION_TIMEOUT=30m
export AKASHIC_SESSION_SECURE_COOKIES=true

# Deployment configuration
export AKASHIC_DEPLOYMENT_ENVIRONMENT=production

# Timezone
export AKASHIC_TZ=Canada/Mountain
```

## Configuration File Locations

ConfigManager searches for configuration files in this order:

1. Specified config file (`--config path/to/config.yaml`)
2. `./config.yaml` (default name in current directory)
3. `./config/config.yaml`
4. `./configs/config.yaml`
5. `$HOME/.akashic/config.yaml`
6. `$HOME/.config/akashic/config.yaml`
7. `/etc/akashic/config.yaml`
8. `/usr/local/etc/akashic/config.yaml`

## Environment Variable Expansion

The configuration system supports automatic environment variable expansion in YAML files:

```yaml
database:
  postgres:
    host: "localhost"
    port: ${AKASHIC_DATABASE_POSTGRES_HOST_PORT}
    username: ${AKASHIC_DATABASE_POSTGRES_USERNAME}
    password: ${AKASHIC_DATABASE_POSTGRES_PASSWORD}
```

**Features:**
- ✅ **Safe Expansion**: Variables are expanded before YAML parsing, preserving types
- ✅ **Fallback Support**: Uses Viper's environment variable override as fallback
- ✅ **Verbose Logging**: Shows when environment variables are expanded (with `--verbose`)

## Graceful Shutdown Integration

The configuration system integrates with application lifecycle management:

```go
// ConfigManager automatically registers cleanup functions
app := akashic.NewAkashicApp()
defer app.Close() // Handles all closer functions including config cleanup

// Or manually register cleanup functions
app.AddCloser(func() {
    // Custom cleanup logic
})
```

## Validation

The system provides comprehensive validation for startup safety:

```go
// Validation is performed automatically during LoadConfig()
cfg := manager.GetConfig()
// Configuration is automatically validated before being returned
```

### Validation Rules

**Required Fields:**
- Server host and port for both auth and control servers (must be non-empty, valid port range)
- Database connection details (PostgreSQL: host, database, username, password)
- Database connection details (Redis: host)

**Type Safety:**
- Safe type assertions with proper nil checking
- Graceful handling of missing or invalid configuration values
- Comprehensive error messages for debugging

**Logging Configuration:**
- Required fields for each sink type (file_path for file sinks, loki_url for Loki sinks)
- Valid sink types, levels, and formats
- Proper error handling for invalid logging configurations

## Type Safety and Error Handling

The configuration system uses safe type assertions and comprehensive error handling:

```go
// Safe type assertions prevent runtime panics
sinkType, ok := sinkMap["type"].(string)
if !ok {
    // Handle missing or invalid type gracefully
    manager.VerbosePrintlnf("invalid or missing sink type")
    continue
}

// Error handling for configuration parsing
if err := manager.LoadConfig(); err != nil {
    return fmt.Errorf("failed to load configuration: %v", err)
}
```

**Key Safety Features:**
- ✅ **No Runtime Panics**: All type assertions use the safe two-value form
- ✅ **Graceful Degradation**: Invalid configurations are skipped with warnings
- ✅ **Comprehensive Logging**: Verbose mode shows detailed configuration processing
- ✅ **Validation Before Use**: All critical fields are validated during startup

## Error Handling

The configuration system provides robust error handling for various scenarios:

**Common Error Scenarios:**
- Missing required configuration values (gracefully handled with validation errors)
- Invalid YAML syntax in configuration files
- Type assertion failures (prevented with safe type checking)
- Environment variable expansion failures
- Missing .env files (handled gracefully, not treated as errors)

**Error Flow:**
```go
// Configuration errors are returned with context
if err := manager.LoadConfig(); err != nil {
    // Errors include detailed information about what failed
    log.Fatalf("Configuration failed: %v", err)
}

// Verbose mode provides additional debugging information
manager.VerbosePrintlnf("Config file error: %v; using defaults", err)
```

## Integration with Cobra CLI

The package integrates seamlessly with Cobra CLI:

```go
// Register configuration flags
config.RegisterFlags(rootCmd)

// Flags are automatically available:
// --config, -c     : specify configuration file path
// --verbose        : enable verbose logging
// --host, -H       : override server host
// --port, -p       : override server port
```

**Command Line Usage:**
```bash
# Basic usage with verbose output
./akashic --verbose

# Custom configuration file
./akashic --config /path/to/config.yaml --verbose

# Override specific values
./akashic --host 0.0.0.0 --port 9090 --verbose
```

## Best Practices

1. **Use environment variables** for secrets (passwords, tokens) - they are automatically expanded in YAML files
2. **Leverage .env files** for local development - loaded automatically by the configuration system
3. **Use verbose mode** during development for detailed configuration debugging
4. **Validate critical paths** - the system validates essential configuration on startup
5. **Follow the AKASHIC_ prefix** for all environment variables to avoid conflicts
6. **Keep certificates** in a secure location with proper file permissions
7. **Use the AkashicApp architecture** for automatic lifecycle management

## Interface-Based Architecture

The configuration system uses interfaces to maintain clean architecture:

```go
// VerbosePrinter interface allows loose coupling
type VerbosePrinter interface {
    VerbosePrintlnf(format string, args ...interface{})
}

// ConfigManager depends on interface, not concrete implementation
func NewConfigManager(cmd *cobra.Command, verbosePrinter VerbosePrinter) (*ConfigManager, error)
```

**Benefits:**
- ✅ **No Cyclic Dependencies**: Interfaces break import cycles
- ✅ **Testability**: Easy to mock for unit testing
- ✅ **Extensibility**: New implementations can be added without changing core logic
- ✅ **Separation of Concerns**: Each component has clear responsibilities

## Development vs Production

**Development Mode:**
- Uses `.env` files for local configuration
- Verbose logging available for debugging
- Comprehensive error messages and warnings

**Production Mode:**
- Relies on environment variables and configuration files
- Graceful error handling without exposing internals
- Optimized for startup performance

## Future Expansion

The configuration system is architected for incremental expansion:

**Planned Additions:**
- **OAuth 2.1 & OIDC Configuration**: Authorization flows, token settings, PKCE requirements
- **Security Policies**: Rate limiting, CORS, content security policies
- **Authentication Methods**: LDAP, Kerberos, multi-factor authentication
- **Client Management**: 3rd party service registration and management
- **Advanced TLS**: Certificate rotation, ACME integration
- **Observability**: Metrics, tracing, and monitoring configuration

**Design Philosophy:**
The current architecture ensures backward compatibility while supporting future features through:
- Interface-based design for extensibility
- Comprehensive validation framework for new configuration sections
- Safe type handling that can accommodate new field types
- Environment variable expansion supporting dynamic configuration