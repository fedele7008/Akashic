# Control Server API Documentation

## Overview

The Control Server provides management and administrative APIs for the Akashic IDP. It handles server lifecycle management, configuration control, and system monitoring.

**Default Address:** `http://127.0.0.1:8081` (localhost only)

**Purpose:**
- Manage Auth Server lifecycle (start, stop, restart)
- Monitor system status and health
- Handle configuration reloading
- Control application shutdown

## Security Model

The Control Server binds to localhost (127.0.0.1) by default for security:
- **Local access only** - Prevents external network access
- **No authentication** (current phase) - Suitable for localhost-only access
- **Future:** mTLS authentication for remote access with client certificates

---

## API Endpoints

### 1. Health Check

Verify the control server is responding.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy"
  }
}
```

**Status Codes:**
- `200 OK` - Control server is healthy
- `405 Method Not Allowed` - Wrong HTTP method

**Example:**
```bash
curl http://localhost:8081/health
```

---

### 2. System Status

Get detailed status of both control and auth servers.

**Endpoint:** `GET /status`

**Response:**
```json
{
  "success": true,
  "data": {
    "control_server": {
      "state": "running",
      "address": "127.0.0.1:8081"
    },
    "auth_server": {
      "state": "running",
      "uptime": "1h23m45s",
      "started_at": "2025-10-05T14:30:00Z",
      "address": "0.0.0.0:8080"
    },
    "uptime": "1h23m45s",
    "pid": 12345
  }
}
```

**Auth Server States:**
- `stopped` - Server is not running
- `starting` - Server is in the process of starting
- `running` - Server is running normally
- `stopping` - Server is shutting down
- `error` - Server encountered an error

**Status Codes:**
- `200 OK` - Status retrieved successfully
- `405 Method Not Allowed` - Wrong HTTP method

**Example:**
```bash
curl http://localhost:8081/status
```

---

### 3. Get Configuration

Retrieve the current sanitized configuration.

**Endpoint:** `GET /config`

**Response:**
```json
{
  "success": true,
  "data": {
    "server": {
      "auth": {
        "host": "0.0.0.0",
        "port": 8080
      },
      "control": {
        "host": "127.0.0.1",
        "port": 8081
      }
    },
    "database": {
      "postgres": {
        "host": "localhost",
        "port": 5432,
        "database": "akashic",
        "username": "akashic",
        "password": "[REDACTED]"
      },
      "redis": {
        "host": "localhost",
        "port": 6379,
        "password": "[REDACTED]"
      }
    },
    "session": {
      "timeout": "30m0s",
      "cookie_name": "akashic_session"
    },
    "deployment": {
      "environment": "development",
      "debug": true
    }
  }
}
```

**Sanitization:**
- All password fields are replaced with `[REDACTED]`
- Sensitive keys and secrets are masked
- Safe for logging and debugging

**Status Codes:**
- `200 OK` - Configuration retrieved successfully
- `405 Method Not Allowed` - Wrong HTTP method

**Example:**
```bash
curl http://localhost:8081/config
```

---

### 4. Reload Configuration

Hot-reload the configuration from disk without restarting servers.

**Endpoint:** `POST /config/reload`

**Request:** No body required

**Success Response:**
```json
{
  "success": true,
  "data": {
    "message": "Configuration reloaded successfully"
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "error": {
    "code": "CONFIG_RELOAD_FAILED",
    "message": "Failed to reload configuration",
    "details": {
      "error": "yaml: unmarshal errors:\n  line 5: field invalid_field not found"
    }
  }
}
```

**Status Codes:**
- `200 OK` - Configuration reloaded successfully
- `405 Method Not Allowed` - Wrong HTTP method
- `500 Internal Server Error` - Failed to reload config (invalid YAML, validation errors, etc.)

**Side Effects:**
- Logger is automatically reconfigured with new settings
- Changes take effect immediately
- Running servers continue with new configuration

**Example:**
```bash
curl -X POST http://localhost:8081/config/reload
```

---

### 5. Start Auth Server

Start the authentication server.

**Endpoint:** `POST /auth/start`

**Request:** No body required

**Success Response:**
```json
{
  "success": true,
  "data": {
    "message": "Auth server started successfully",
    "status": {
      "state": "running",
      "uptime": "0s",
      "started_at": "2025-10-05T16:00:00Z",
      "address": "0.0.0.0:8080"
    }
  }
}
```

**Error Response (Already Running):**
```json
{
  "success": false,
  "error": {
    "code": "AUTH_SERVER_RUNNING",
    "message": "Auth server is already running",
    "details": null
  }
}
```

**Error Response (Port Conflict):**
```json
{
  "success": false,
  "error": {
    "code": "AUTH_SERVER_ERROR",
    "message": "Failed to start auth server",
    "details": {
      "error": "failed to bind to 0.0.0.0:8080: listen tcp 0.0.0.0:8080: bind: address already in use"
    }
  }
}
```

**Status Codes:**
- `200 OK` - Auth server started successfully
- `405 Method Not Allowed` - Wrong HTTP method
- `409 Conflict` - Server is already running/starting/stopping
- `500 Internal Server Error` - Failed to start (port conflict, etc.)

**State Transitions:**
- `stopped` → `starting` → `running` (success)
- `stopped` → `starting` → `error` (failure)

**Example:**
```bash
curl -X POST http://localhost:8081/auth/start
```

---

### 6. Stop Auth Server

Gracefully stop the authentication server.

**Endpoint:** `POST /auth/stop`

**Request:** No body required

**Success Response:**
```json
{
  "success": true,
  "data": {
    "message": "Auth server stopped successfully",
    "status": {
      "state": "stopped"
    }
  }
}
```

**Error Response (Already Stopped):**
```json
{
  "success": false,
  "error": {
    "code": "AUTH_SERVER_NOT_RUNNING",
    "message": "Auth server is already stopped",
    "details": null
  }
}
```

**Status Codes:**
- `200 OK` - Auth server stopped successfully
- `405 Method Not Allowed` - Wrong HTTP method
- `409 Conflict` - Server is already stopped/starting/stopping
- `500 Internal Server Error` - Failed to stop gracefully

**State Transitions:**
- `running` → `stopping` → `stopped` (success)
- `running` → `stopping` → `error` (failure)
- `error` → `stopped` (recovery from error state)

**Graceful Shutdown:**
- In-flight requests are completed (up to 10 second timeout)
- Server stops accepting new requests immediately
- Connections are closed cleanly

**Example:**
```bash
curl -X POST http://localhost:8081/auth/stop
```

---

### 7. Restart Auth Server

Restart the authentication server (stop then start).

**Endpoint:** `POST /auth/restart`

**Request:** No body required

**Success Response:**
```json
{
  "success": true,
  "data": {
    "message": "Auth server restarted successfully",
    "status": {
      "state": "running",
      "uptime": "0s",
      "started_at": "2025-10-05T16:05:00Z",
      "address": "0.0.0.0:8080"
    }
  }
}
```

**Error Response (Transitional State):**
```json
{
  "success": false,
  "error": {
    "code": "AUTH_SERVER_ERROR",
    "message": "Cannot restart during transitional state",
    "details": {
      "current_state": "starting"
    }
  }
}
```

**Status Codes:**
- `200 OK` - Auth server restarted successfully
- `405 Method Not Allowed` - Wrong HTTP method
- `409 Conflict` - Server is in transitional state (starting/stopping)
- `500 Internal Server Error` - Failed to restart

**State Transitions:**
- `running` → `stopping` → `stopped` → `starting` → `running` (success)
- `stopped` → `starting` → `running` (if already stopped)
- `error` → `stopped` → `starting` → `running` (recovery)

**Behavior:**
- Stops the server if currently running
- Waits 500ms for clean shutdown
- Starts the server with fresh configuration
- Useful after configuration changes

**Example:**
```bash
curl -X POST http://localhost:8081/auth/restart
```

---

### 8. Quit Application

Trigger graceful shutdown of the entire Akashic application.

**Endpoint:** `POST /server/quit`

**Request:** No body required

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Shutdown initiated"
  }
}
```

**Status Codes:**
- `200 OK` - Shutdown initiated successfully
- `405 Method Not Allowed` - Wrong HTTP method

**Shutdown Process:**
1. Response is sent to client
2. Brief 100ms delay to ensure response delivery
3. Shutdown signal is triggered
4. Auth server stops gracefully (if running)
5. Control server stops gracefully
6. Logger and other resources are closed (LIFO order)
7. Application exits

**Example:**
```bash
curl -X POST http://localhost:8081/server/quit
```

**Note:** This endpoint always succeeds (returns 200) even if shutdown encounters errors. Check server logs for shutdown issues.

---

## State Machine

The Auth Server lifecycle is managed by a state machine to prevent invalid operations.

### State Diagram

```
     ┌─────────┐
     │ Stopped │◄─────────┐
     └────┬────┘          │
          │               │
      [START]         [STOP]
          │               │
          ▼               │
     ┌──────────┐         │
     │ Starting │         │
     └────┬─────┘         │
          │               │
    [Success]             │
          │               │
          ▼               │
     ┌─────────┐          │
     │ Running ├──────────┘
     └────┬────┘
          │
     [Error]
          │
          ▼
     ┌───────┐
     │ Error │
     └───┬───┘
         │
    [STOP]
         │
         ▼
    ┌─────────┐
    │ Stopped │
    └─────────┘
```

### Valid State Transitions

| From State | Operation | To State | Result |
|------------|-----------|----------|--------|
| `stopped` | START | `starting` → `running` | ✅ Success |
| `stopped` | START | `starting` → `error` | ❌ Start failed |
| `stopped` | STOP | N/A | ❌ Already stopped |
| `stopped` | RESTART | `starting` → `running` | ✅ Success |
| `starting` | START | N/A | ❌ Already starting |
| `starting` | STOP | N/A | ❌ Wait for start to complete |
| `starting` | RESTART | N/A | ❌ Wait for start to complete |
| `running` | START | N/A | ❌ Already running |
| `running` | STOP | `stopping` → `stopped` | ✅ Success |
| `running` | RESTART | `stopping` → `stopped` → `starting` → `running` | ✅ Success |
| `stopping` | START | N/A | ❌ Wait for stop to complete |
| `stopping` | STOP | N/A | ❌ Already stopping |
| `stopping` | RESTART | N/A | ❌ Wait for stop to complete |
| `error` | START | N/A | ❌ Stop first to clear error |
| `error` | STOP | `stopped` | ✅ Recovery |
| `error` | RESTART | `stopped` → `starting` → `running` | ✅ Recovery |

---

## Error Responses

All endpoints use a standardized error response format.

### Error Response Structure

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "additional": "context"
    }
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `METHOD_NOT_ALLOWED` | 405 | Invalid HTTP method for endpoint |
| `AUTH_SERVER_RUNNING` | 409 | Auth server is already running |
| `AUTH_SERVER_NOT_RUNNING` | 409 | Auth server is already stopped |
| `AUTH_SERVER_STARTING` | 409 | Auth server is in starting state |
| `AUTH_SERVER_STOPPING` | 409 | Auth server is in stopping state |
| `AUTH_SERVER_ERROR` | 500 | Generic auth server error |
| `CONFIG_RELOAD_FAILED` | 500 | Configuration reload failed |
| `ENCODING_ERROR` | 500 | Failed to encode JSON response |

---

## Configuration

The Control Server is configured via the Config Manager:

```yaml
server:
  control:
    host: "127.0.0.1"     # Localhost only for security
    port: 8081            # Default port
```

**Environment Variables:**
```bash
AKASHIC_SERVER_CONTROL_HOST=127.0.0.1
AKASHIC_SERVER_CONTROL_PORT=8081
```

**Security Recommendations:**
- Keep `host: "127.0.0.1"` for local-only access
- For remote access, implement mTLS authentication (future phase)
- Use firewall rules to restrict access

---

## Testing

### Manual Testing

```bash
# Check control server health
curl http://localhost:8081/health

# Get system status
curl http://localhost:8081/status

# Get sanitized config
curl http://localhost:8081/config

# Start auth server
curl -X POST http://localhost:8081/auth/start

# Stop auth server
curl -X POST http://localhost:8081/auth/stop

# Restart auth server
curl -X POST http://localhost:8081/auth/restart

# Reload configuration
curl -X POST http://localhost:8081/config/reload

# Graceful shutdown
curl -X POST http://localhost:8081/server/quit
```

### Testing State Transitions

```bash
# Test: Start when already running (should fail with 409)
curl -X POST http://localhost:8081/auth/start
curl -X POST http://localhost:8081/auth/start

# Test: Stop when already stopped (should fail with 409)
curl -X POST http://localhost:8081/auth/stop
curl -X POST http://localhost:8081/auth/stop

# Test: Restart from any state (should succeed)
curl -X POST http://localhost:8081/auth/restart
```

### Testing Configuration Reload

```bash
# Modify config.yaml
vim configs/config.yaml

# Reload without restart
curl -X POST http://localhost:8081/config/reload

# Verify changes
curl http://localhost:8081/config
```

---

## Implementation Details

### Server Timeouts

```go
CtrlServerReadTimeout             = 15 * time.Second
CtrlServerWriteTimeout            = 15 * time.Second
CtrlServerIdleTimeout             = 60 * time.Second
CtrlServerGracefulShutdownTimeout = 10 * time.Second
```

### Pre-Bind Pattern

The server uses a pre-bind listener pattern for immediate port conflict detection:

```go
ln, err := net.Listen("tcp", addr)
if err != nil {
    return fmt.Errorf("failed to bind to %s: %v", addr, err)
}

go func() {
    s.server.Serve(ln)
}()
```

### Thread Safety

- State Manager uses `sync.RWMutex` for thread-safe state transitions
- Configuration Manager has internal locking for concurrent access
- All state changes are atomic

---

## Package Structure

```
pkg/server/control/
├── README.md       # This documentation
├── server.go       # Server implementation and lifecycle
├── routes.go       # Route registration
├── handlers.go     # HTTP request handlers
├── state.go        # State machine for auth server lifecycle
└── sanitize.go     # Configuration sanitization
```

---

## Future Enhancements

### Security
- mTLS authentication for remote access
- Client certificate validation
- API key or token-based authentication
- Request rate limiting

### Monitoring
- Prometheus metrics endpoint (`/metrics`)
- Detailed health checks with component status
- Performance metrics and statistics

### Configuration
- Partial configuration updates (PATCH /config)
- Configuration rollback on validation failure
- Configuration history and versioning

---

## Related Documentation

- [Auth Server API](../auth/README.md) - Authentication server endpoints
- [Response Package](../response/README.md) - Standardized JSON responses
- [Configuration](../../config/README.md) - Configuration management
- [State Machine](./state.go) - Implementation details
