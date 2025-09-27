# Config Package Demo

This demo command tests the functionality of the `pkg/config` package to verify that all components work correctly without formal unit tests.

## How to Run

```bash
# Build and run the demo
go build -o build/config-demo ./cmd/config-demo
./build/config-demo
```

## What the Demo Tests

### ✅ Working Features

1. **Default Configuration Loading**
   - Loads default values when no config file is present
   - Properly applies FillDefaults() method
   - All server and database defaults are correctly set

2. **Environment Variable Overrides**
   - Successfully overrides configuration values with environment variables
   - Correctly parses different data types (strings, integers, booleans)
   - Environment-specific configuration loading works

3. **Configuration Manager**
   - Creates manager instance successfully with default values
   - Runtime configuration updates work correctly
   - setServerConfig() method properly updates auth and control server settings

4. **Validation System**
   - Detects invalid port numbers (>65535)
   - Validates missing certificate files when TLS is enabled
   - Comprehensive validation error reporting works

5. **Example Config Generation**
   - GenerateExampleConfig() creates valid YAML files
   - Generated files contain all essential configuration sections

### ❌ Issues Found

1. **YAML File Loading (Critical Issue)**
   - Cannot load configuration from YAML files
   - Error: `cannot unmarshal !!str into common.Nullable[string]`
   - Root cause: `common.Nullable[T]` type lacks YAML marshaling/unmarshaling methods

### 🔧 What Needs to be Fixed

The `pkg/common/nullable_types.go` file needs YAML marshaling support. The `Nullable[T]` type needs these methods:

```go
// UnmarshalYAML implements yaml.Unmarshaler
func (n *Nullable[T]) UnmarshalYAML(value *yaml.Node) error {
    var v T
    if err := value.Decode(&v); err != nil {
        return err
    }
    n.Value = v
    n.Valid = true
    return nil
}

// MarshalYAML implements yaml.Marshaler
func (n Nullable[T]) MarshalYAML() (interface{}, error) {
    if n.Valid {
        return n.Value, nil
    }
    return nil, nil
}
```

## Configuration Features Verified

### Server Configuration
- ✅ Auth server (OAuth/OIDC endpoints): host, port
- ✅ Control server (mTLS management): host, port, TLS settings
- ✅ TLS configuration validation (cert files, CA, client auth)

### Database Configuration
- ✅ PostgreSQL: host, port, database, credentials, connection pool
- ✅ Redis: host, port, password, DB selection, pool settings

### Session Management
- ✅ Timeout, secure cookies, SameSite, cookie name/path

### Logging Integration
- ✅ Service name and environment configuration
- ✅ Multi-channel logging (app, security, audit)
- ✅ Sink configuration for different output types

### Deployment Settings
- ✅ Environment selection (development/staging/production)
- ✅ Debug flag configuration

## Next Steps

1. **Fix YAML marshaling** in `pkg/common/nullable_types.go`
2. **Re-run demo** to verify file loading works
3. **Test hot-reload functionality** (currently disabled in demo)
4. **Test change listeners** for configuration updates

## Usage as Development Tool

This demo serves as:
- **Integration test** for the config package
- **Documentation** of working features
- **Issue detector** for configuration problems
- **Example** of how to use the config package in applications