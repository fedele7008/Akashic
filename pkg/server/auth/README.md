# Auth Server API Documentation

## Overview

The Auth Server is the primary authentication server for Akashic IDP, providing OAuth 2.1 and OpenID Connect (OIDC) endpoints. Currently implements health check and readiness endpoints, with full OAuth/OIDC flows to be implemented in future phases.

**Default Address:** `http://0.0.0.0:8080`

**Purpose:**
- Serve OAuth 2.1 authorization and token endpoints
- Provide OIDC authentication flows
- Handle user authentication requests
- Manage client authentication

## Architecture

The Auth Server:
- Runs independently of the Control Server
- Can be started/stopped via Control API or auto-started on application launch
- Uses graceful shutdown with configurable timeout (default: 10 seconds)
- Pre-binds to port for immediate conflict detection

## API Endpoints

### Health Check

Check if the auth server is responding to requests.

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
- `200 OK` - Server is healthy
- `405 Method Not Allowed` - Wrong HTTP method used

**Example:**
```bash
curl http://localhost:8080/health
```

---

### Readiness Check

Check if the auth server is ready to handle authentication requests. In the future, this will verify database connections, external service availability, etc.

**Endpoint:** `GET /ready`

**Response:**
```json
{
  "success": true,
  "data": {
    "ready": true,
    "checks": {
      "server": "ok"
    }
  }
}
```

**Status Codes:**
- `200 OK` - Server is ready
- `405 Method Not Allowed` - Wrong HTTP method used

**Future Checks:**
- Database connectivity (PostgreSQL, Redis)
- LDAP/Kerberos connection status
- Key management system availability

**Example:**
```bash
curl http://localhost:8080/ready
```

---

## Error Responses

All endpoints use a standardized error response format:

```json
{
  "success": false,
  "error": {
    "code": "METHOD_NOT_ALLOWED",
    "message": "POST method not allowed",
    "details": {
      "allowed_methods": ["GET"],
      "received_method": "POST"
    }
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `METHOD_NOT_ALLOWED` | 405 | Invalid HTTP method for endpoint |
| `ENCODING_ERROR` | 500 | Failed to encode JSON response |

---

## Configuration

The Auth Server is configured via the Config Manager:

```yaml
server:
  auth:
    host: "0.0.0.0"      # Listen on all interfaces
    port: 8080            # Default port
```

**Environment Variables:**
```bash
AKASHIC_SERVER_AUTH_HOST=0.0.0.0
AKASHIC_SERVER_AUTH_PORT=8080
```

---

## Server Lifecycle

The Auth Server supports the following lifecycle operations (managed via Control Server):

1. **Start** - Bind to port and begin accepting requests
2. **Stop** - Graceful shutdown with request completion
3. **Restart** - Stop then start with brief pause

**Auto-Start Behavior:**
- By default, the auth server starts automatically when the application launches
- Use `--no-auto-start` flag to prevent auto-start
- When auto-start is disabled, start via Control API: `POST http://localhost:8081/auth/start`

---

## Future Endpoints

The following endpoints will be implemented in future phases:

### OAuth 2.1 Endpoints
- `GET /authorize` - Authorization endpoint
- `POST /token` - Token endpoint
- `POST /revoke` - Token revocation
- `POST /introspect` - Token introspection

### OIDC Endpoints
- `GET /.well-known/openid-configuration` - Discovery document
- `GET /jwks` - JSON Web Key Set
- `GET /userinfo` - User information endpoint

### Session Management
- `GET /logout` - End user session
- `POST /logout` - Logout with token

---

## Security Considerations

### Current Phase
- Server runs on all interfaces (0.0.0.0) by default - **configure appropriately for production**
- No authentication required for health/ready endpoints
- Plain HTTP - **use reverse proxy with TLS in production**

### Future Phases
- mTLS for internal communication with Control Server
- Client authentication for OAuth flows
- Rate limiting via Guardian component
- Request validation and sanitization

---

## Testing

### Manual Testing

```bash
# Test health endpoint
curl http://localhost:8080/health

# Test readiness
curl http://localhost:8080/ready

# Test method validation (should return 405)
curl -X POST http://localhost:8080/health
```

### Integration Testing

The auth server can be controlled programmatically via the Control Server API. See `pkg/server/control/README.md` for details.

---

## Implementation Details

### Server Timeouts

```go
AuthServerReadTimeout             = 15 * time.Second
AuthServerWriteTimeout            = 15 * time.Second
AuthServerIdleTimeout             = 60 * time.Second
AuthServerGracefulShutdownTimeout = 10 * time.Second
```

### Pre-Bind Pattern

The server uses a pre-bind listener pattern to detect port conflicts immediately:

```go
ln, err := net.Listen("tcp", addr)
if err != nil {
    return fmt.Errorf("failed to bind to %s: %v", addr, err)
}

go func() {
    s.server.Serve(ln)
}()
```

This ensures:
- Immediate port conflict detection
- No race conditions during startup
- Clean error handling before goroutine launch

---

## Package Structure

```
pkg/server/auth/
├── README.md       # This documentation
├── server.go       # Server implementation and lifecycle
├── routes.go       # Route registration
└── handlers.go     # HTTP request handlers
```

---

## Related Documentation

- [Control Server API](../control/README.md) - Management and lifecycle control
- [Response Package](../response/README.md) - Standardized JSON responses
- [Configuration](../../config/README.md) - Configuration management
