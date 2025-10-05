# Configuration Package

The configuration management system for Akashic provides robust, production-ready configuration with hot-reload capabilities, environment variable expansion, type-safe parsing, and integration with the application lifecycle.

## Overview

This package provides a **comprehensive configuration system** with the following features:

- **Hot-Reload Configuration**: Reload configuration at runtime via Control API without restarting servers
- **Logger Reconfiguration**: Automatically reconfigure logging system when configuration changes
- **Server Configuration**: Auth server and control plane settings with mTLS support
- **Database Configuration**: PostgreSQL and Redis connections with environment variable support
- **Session Management**: Cookie and session security settings
- **Logging Configuration**: Multi-sink logging system with stdout, file, and Loki support
- **Deployment Settings**: Environment-specific configuration management
- **Type Safety**: Safe type assertions with comprehensive validation
- **Graceful Shutdown**: Integration with application lifecycle management

**Current Status**: Production-ready configuration architecture with hot-reload, validation, and extensible design.

## Architecture

The package uses **ConfigManager** with Viper for robust configuration handling:

- **ConfigManager**: Primary configuration interface with hot-reload and change notification
- **Interface-Based Design**: Uses `common.AkashicApp` interface to avoid cyclic dependencies
- **Environment Variable Expansion**: Automatic `${VAR}` expansion in YAML files with `AKASHIC_` prefix
- **Type Safety**: Safe type assertions with proper nil checking and error handling
- **Hot-Reload Support**: Runtime configuration updates with automatic logger reconfiguration
- **Validation**: Comprehensive configuration validation for startup safety

## Quick Start

### Using with AkashicApp (Recommended)

The most common usage is within the AkashicApp architecture:

```go
import (
    "akashic/akashic/pkg/akashic"
    "github.com/spf13/cobra"
)

func main() {
    cmd := &cobra.Command{Use: "akashic"}
    config.RegisterFlags(cmd)

    app := akashic.NewAkashicApp()
    if err := app.Init(cmd, args); err != nil {
        log.Fatal(err)
    }
    defer app.Close() // Automatically handles ConfigManager cleanup

    // Configuration is available through app.Config
    cfg := app.Config.GetConfig()

    // Run the application
    if err := app.Run(cmd, args); err != nil {
        log.Fatal(err)
    }
}
```

### Basic Usage with ConfigManager

```go
package main

import (
    "akashic/akashic/pkg/config"
    "github.com/spf13/cobra"
)

func main() {
    // Create a Cobra command
    cmd := &cobra.Command{Use: "example"}
    config.RegisterFlags(cmd)

    // Create application (implements common.AkashicApp interface)
    app := akashic.NewAkashicApp()

    // Create configuration manager
    manager, err := config.NewConfigManager(cmd, app)
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
}
```

### Command Line Usage

```bash
# Run with verbose output
./akashic run --verbose

# Use custom configuration file
./akashic run --config /path/to/config.yaml --verbose

# Prevent auth server auto-start
./akashic run --no-auto-start

# Override server settings
./akashic run --host 0.0.0.0 --port 9090
```

## Configuration Structure

### Essential Configuration

```yaml
# Server configuration for API endpoints and control plane
server:
  auth:
    host: "0.0.0.0"          # Auth server host (OAuth/OIDC endpoints)
    port: 8080               # Auth server port
  control:
    host: "127.0.0.1"        # Control server host (management API)
    port: 8081               # Control server port

# Database connections with environment variable support
database:
  postgres:
    host: "localhost"
    port: 5432
    database: "akashic"
    username: "akashic"
    password: "${AKASHIC_DATABASE_POSTGRES_PASSWORD}"  # Use environment variable
    ssl_mode: "require"
    max_connections: 100
    max_idle_connections: 10
    connection_lifetime: "1h"
  redis:
    host: "localhost"
    port: 6379
    password: "${AKASHIC_DATABASE_REDIS_PASSWORD}"     # Use environment variable
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

# Logging configuration with multiple channels and sinks
logging:
  service_name: "akashic"
  encoder:
    timestamp_key: "timestamp"
    time_format: "Mon Jan _2 15:04:05 MST 2006" # UnixDate format
    level_key: "level"
    name_key: "logger"
    caller_key: "caller"
    message_key: "message"
    stacktrace_key: "stacktrace"

  # Application logging channel
  app:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2  # 0=debug, 1=info, 2=warn, 3=error, 4=fatal
    sinks:
      - type: "stdout"
        enabled: true
        level: "debug"
        format: "text"
      - type: "file"
        enabled: true
        level: "debug"
        format: "text"
        file_path: "./logs/app.log"
        file_mode: "rolling"  # append, truncate, rolling
        max_size_mb: 100
        max_backups: 3
        max_age_days: 30
      - type: "loki"
        enabled: true
        level: "info"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true
        batch_size: 100
        batch_wait: "1s"

  # Security logging channel
  security:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2
    sinks:
      - type: "stdout"
        enabled: true
        level: "info"
        format: "json"
      - type: "file"
        enabled: true
        level: "info"
        format: "json"
        file_path: "./logs/security.log"
        file_mode: "append"
      - type: "loki"
        enabled: true
        level: "info"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true

  # Audit logging channel
  audit:
    enabled: true
    show_caller: true
    show_stacktrace: true
    stacktrace_level: 2
    sinks:
      - type: "file"
        enabled: true
        level: "info"
        format: "json"
        file_path: "./logs/audit.log"
        file_mode: "append"
      - type: "loki"
        enabled: true
        level: "info"
        loki_url: "${AKASHIC_LOKI_API_URL}"
        compress: true

# Deployment settings
deployment:
  environment: "development"             # development, staging, production
  debug: false
```

## Hot-Reload Configuration

One of the key features is runtime configuration reloading via the Control API:

### Reloading Configuration

```bash
# Reload configuration without restarting
curl -X POST http://localhost:8081/config/reload
```

**What Happens During Reload:**

1. Configuration file is re-read from disk
2. Environment variables are re-expanded
3. Configuration is validated
4. Logger is automatically reconfigured with new settings
5. Changes take effect immediately

**Example Response:**

```json
{
  "success": true,
  "data": {
    "message": "Configuration reloaded successfully"
  }
}
```

### Logger Reconfiguration

When configuration is reloaded, the logger is automatically reconfigured:

```go
// In AkashicApp.Init()
app.Config.SetLoggerReconfigureFunction(app.Logger.Reconfigure)

// When config is reloaded via POST /config/reload
// The logger reconfigure function is automatically called
```

**What Can Be Hot-Reloaded:**

- ✅ Logging levels and sinks
- ✅ Logging formats (text/JSON)
- ✅ File paths and rotation settings
- ✅ Loki endpoints and compression
- ✅ Session timeout settings
- ✅ Database connection pool settings (new connections only)

**What Requires Restart:**

- ❌ Server host and port changes
- ❌ TLS certificate changes
- ❌ Database hostname changes

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
export AKASHIC_DATABASE_POSTGRES_USERNAME=admin
export AKASHIC_DATABASE_POSTGRES_PASSWORD=postgres123

export AKASHIC_DATABASE_REDIS_HOST=localhost
export AKASHIC_DATABASE_REDIS_PORT=6379
export AKASHIC_DATABASE_REDIS_PASSWORD=redis123

# Logging configuration
export AKASHIC_LOKI_API_URL="http://localhost:3100/loki/api/v1/push"

# Session configuration
export AKASHIC_SESSION_TIMEOUT=30m
export AKASHIC_SESSION_SECURE_COOKIES=true

# Deployment configuration
export AKASHIC_DEPLOYMENT_ENVIRONMENT=production
export AKASHIC_DEPLOYMENT_DEBUG=false
```

## Configuration File Locations

ConfigManager searches for configuration files in this order:

1. Specified config file (`--config path/to/config.yaml`)
2. `./config.yaml` (current directory)
3. `./config/config.yaml`
4. `./configs/config.yaml`
5. `$HOME/.akashic/config.yaml`
6. `$HOME/.config/akashic/config.yaml`
7. `/etc/akashic/config.yaml`
8. `/usr/local/etc/akashic/config.yaml`

**Supported Formats:**
- YAML (`.yaml`, `.yml`)
- JSON (`.json`)

## Environment Variable Expansion

The configuration system supports automatic environment variable expansion in YAML files:

```yaml
database:
  postgres:
    host: "localhost"
    port: ${AKASHIC_DATABASE_POSTGRES_PORT}
    username: ${AKASHIC_DATABASE_POSTGRES_USERNAME}
    password: ${AKASHIC_DATABASE_POSTGRES_PASSWORD}

logging:
  app:
    sinks:
      - type: "loki"
        loki_url: "${AKASHIC_LOKI_API_URL}"
```

**Features:**
- ✅ **Safe Expansion**: Variables are expanded before YAML parsing, preserving types
- ✅ **Fallback Support**: Uses Viper's environment variable override as fallback
- ✅ **Verbose Logging**: Shows when environment variables are expanded (with `--verbose`)
- ✅ **Hot-Reload Compatible**: Re-expands variables during configuration reload

## Command-Line Flags

The package provides several command-line flags:

| Flag | Short | Type | Description | Viper Key |
|------|-------|------|-------------|-----------|
| `--config` | `-c` | string | Configuration file path | N/A |
| `--verbose` | N/A | bool | Enable verbose output | N/A |
| `--host` | `-H` | string | Override auth server host | `server.auth.host` |
| `--port` | `-p` | int | Override auth server port | `server.auth.port` |
| `--no-auto-start` | N/A | bool | Don't auto-start auth server | N/A |

**Example Usage:**

```bash
# Basic usage with verbose output
./akashic run --verbose

# Custom configuration file
./akashic run --config /path/to/config.yaml --verbose

# Override host and port
./akashic run --host 0.0.0.0 --port 9090

# Prevent auth server auto-start (start manually via control API)
./akashic run --no-auto-start
```

## Validation

The system provides comprehensive validation for startup safety:

### Validation Rules

**Server Configuration:**
- ✅ Host must be non-empty
- ✅ Port must be between 1 and 65535
- ✅ Both auth and control servers must have valid settings

**Database Configuration:**
- ✅ PostgreSQL: host, database, username, and password required
- ✅ Redis: host required
- ✅ Valid port numbers
- ✅ Connection pool settings must be positive

**Session Configuration:**
- ✅ Timeout must be parseable duration (e.g., "30m")
- ✅ Cookie name must be non-empty
- ✅ SameSite must be one of: Strict, Lax, None

**Logging Configuration:**
- ✅ Each sink must have valid type (stdout, stderr, file, loki)
- ✅ File sinks must have file_path
- ✅ Loki sinks must have loki_url
- ✅ Valid log levels (debug, info, warn, error, fatal)
- ✅ Valid formats (text, json)

**Error Handling:**

```go
// Validation is performed automatically during LoadConfig()
if err := manager.LoadConfig(); err != nil {
    // Detailed error message with context
    log.Fatalf("Configuration validation failed: %v", err)
}
```

## Graceful Shutdown Integration

The configuration system integrates with application lifecycle management:

```go
// ConfigManager automatically registers cleanup functions
app := akashic.NewAkashicApp()
if err := app.Init(cmd, args); err != nil {
    log.Fatal(err)
}
defer app.Close() // Handles all closer functions including config cleanup

// Or manually register cleanup functions
app.AddCloser(func() {
    // Custom cleanup logic
})
```

**Closer Execution:**
- ✅ Closers execute in LIFO order (Last In, First Out)
- ✅ Panic recovery during closer execution
- ✅ Error aggregation for multiple closer failures

## Type Safety and Error Handling

The configuration system uses safe type assertions and comprehensive error handling:

```go
// Safe type assertions prevent runtime panics
if sinkType, ok := sinkMap["type"].(string); ok {
    // Process sink configuration
} else {
    manager.VerbosePrintlnf("invalid or missing sink type")
    continue
}

// Comprehensive error handling
if err := manager.LoadConfig(); err != nil {
    return fmt.Errorf("failed to load configuration: %v", err)
}
```

**Key Safety Features:**
- ✅ **No Runtime Panics**: All type assertions use the safe two-value form
- ✅ **Graceful Degradation**: Invalid configurations are skipped with warnings
- ✅ **Comprehensive Logging**: Verbose mode shows detailed configuration processing
- ✅ **Validation Before Use**: All critical fields are validated during startup
- ✅ **Atomic Updates**: Configuration reloads are atomic (all-or-nothing)

## Interface-Based Architecture

The configuration system uses interfaces to maintain clean architecture:

```go
// AkashicApp interface allows loose coupling
type AkashicApp interface {
    VerbosePrintlnf(format string, args ...any)
    SetVerbose(verbose bool)
    GetVerbose() bool
}

// ConfigManager depends on interface, not concrete implementation
func NewConfigManager(cmd *cobra.Command, app common.AkashicApp) (*ConfigManager, error)
```

**Benefits:**
- ✅ **No Cyclic Dependencies**: Interfaces break import cycles
- ✅ **Testability**: Easy to mock for unit testing
- ✅ **Extensibility**: New implementations can be added without changing core logic
- ✅ **Separation of Concerns**: Each component has clear responsibilities

## Development vs Production

### Development Mode

```bash
# Use .env file for local development
cp .env.example .env

# Enable verbose logging
./akashic run --verbose

# Use development config
./akashic run --config configs/config.development.yaml --verbose
```

**Features:**
- Uses `.env` files for local configuration
- Verbose logging available for debugging
- Comprehensive error messages and warnings
- Hot-reload friendly for rapid iteration

### Production Mode

```bash
# Set environment variables
export AKASHIC_DEPLOYMENT_ENVIRONMENT=production
export AKASHIC_DATABASE_POSTGRES_PASSWORD=<secure-password>
export AKASHIC_DATABASE_REDIS_PASSWORD=<secure-password>

# Run with production config
./akashic run --config /etc/akashic/config.yaml
```

**Features:**
- Relies on environment variables and configuration files
- Graceful error handling without exposing internals
- Optimized for startup performance
- Hot-reload for zero-downtime configuration updates

## API Integration

The configuration system integrates with the Control Server API:

### Get Current Configuration

```bash
# Get sanitized configuration (passwords redacted)
curl http://localhost:8081/config
```

**Response:**

```json
{
  "success": true,
  "data": {
    "server": {
      "auth": {"host": "0.0.0.0", "port": 8080},
      "control": {"host": "127.0.0.1", "port": 8081}
    },
    "database": {
      "postgres": {
        "host": "localhost",
        "port": 5432,
        "database": "akashic",
        "username": "akashic",
        "password": "[REDACTED]"
      }
    }
  }
}
```

### Reload Configuration

```bash
# Reload configuration without restart
curl -X POST http://localhost:8081/config/reload
```

**Use Cases:**
- Update log levels without restart
- Change log output formats
- Add or remove log sinks
- Update session timeout settings
- Modify database connection pool settings

## Best Practices

1. **Use environment variables** for secrets (passwords, tokens) - they are automatically expanded in YAML files
2. **Leverage .env files** for local development - loaded automatically by the configuration system
3. **Use verbose mode** during development for detailed configuration debugging (`--verbose`)
4. **Test hot-reload** before production deployment to ensure configuration changes work as expected
5. **Follow the AKASHIC_ prefix** for all environment variables to avoid conflicts
6. **Validate after reload** - check `/config` endpoint to verify changes took effect
7. **Use the AkashicApp architecture** for automatic lifecycle management
8. **Monitor logs** during configuration reload to catch validation errors

## Advanced Features

### Custom Decode Hooks

The configuration system uses custom decode hooks for type conversion:

```go
// String to logging enum conversion
func stringToLoggingEnumHookFunc() mapstructure.DecodeHookFunc {
    return func(f, t reflect.Type, data any) (any, error) {
        // Convert "debug" → LogLevelDebug
        // Convert "stdout" → SinkTypeStdout
        // etc.
    }
}

// String to duration conversion
func stringToDurationHookFunc() mapstructure.DecodeHookFunc {
    return func(f, t reflect.Type, data any) (any, error) {
        // Convert "30m" → 30 * time.Minute
        // Convert "1h" → 1 * time.Hour
    }
}
```

### Logger Reconfiguration Callback

```go
// Set logger reconfigure function (called in AkashicApp.Init)
app.Config.SetLoggerReconfigureFunction(app.Logger.Reconfigure)

// Function is automatically invoked during config reload
func (m *ConfigManager) LoadConfig() error {
    // ... load and validate config ...

    // Reconfigure logger if function is set
    if m.loggerReconfigureFn != nil {
        if err := m.loggerReconfigureFn(&m.config.Logging); err != nil {
            return fmt.Errorf("failed to reconfigure logger: %v", err)
        }
    }

    return nil
}
```

## Troubleshooting

### Configuration Not Found

```bash
# Use verbose mode to see search paths
./akashic run --verbose

# Output will show:
# [VERBOSE] Skipping config path with unexpanded variables: $HOME/.akashic
# [VERBOSE] No config file found, using defaults and environment variables
```

**Solution:** Specify config file explicitly:

```bash
./akashic run --config /path/to/config.yaml --verbose
```

### Environment Variable Not Expanding

```yaml
# ❌ Wrong: Missing $ or braces
password: AKASHIC_DATABASE_POSTGRES_PASSWORD

# ✅ Correct: Proper expansion syntax
password: ${AKASHIC_DATABASE_POSTGRES_PASSWORD}
```

### Configuration Reload Failed

```bash
curl -X POST http://localhost:8081/config/reload
```

**Response:**

```json
{
  "success": false,
  "error": {
    "code": "CONFIG_RELOAD_FAILED",
    "message": "Failed to reload configuration",
    "details": {
      "error": "validation failed: logging.app.sinks[0].file_path is required for file sink"
    }
  }
}
```

**Solution:** Fix the configuration file and retry:

1. Check server logs for detailed error
2. Fix the configuration file
3. Retry reload

### Logger Not Reconfiguring

**Problem:** Configuration reloads but logger settings don't change.

**Solution:** Ensure logger reconfigure function is set:

```go
// In AkashicApp.Init()
app.Config.SetLoggerReconfigureFunction(app.Logger.Reconfigure)
```

## Future Expansion

The configuration system is architected for incremental expansion:

### Planned Additions

- **OAuth 2.1 & OIDC Configuration**: Authorization flows, token settings, PKCE requirements
- **Security Policies**: Rate limiting, CORS, content security policies
- **TLS Configuration**: mTLS settings, certificate rotation, ACME integration
- **Authentication Methods**: LDAP, Kerberos, multi-factor authentication
- **Client Management**: Third-party service registration and management
- **Observability**: Metrics, tracing, and monitoring configuration

### Design Philosophy

The current architecture ensures backward compatibility while supporting future features through:

- ✅ **Interface-based design** for extensibility
- ✅ **Comprehensive validation framework** for new configuration sections
- ✅ **Safe type handling** that can accommodate new field types
- ✅ **Environment variable expansion** supporting dynamic configuration
- ✅ **Hot-reload capabilities** for runtime updates
- ✅ **Change notification system** for component coordination

## Related Documentation

- [Control Server API](../server/control/README.md) - Configuration reload endpoint
- [Logging System](../logging/README.md) - Logger reconfiguration details
- [Server Architecture](../server/README.md) - Server configuration usage
- [CLAUDE.md](../../CLAUDE.md) - Project overview and architecture
