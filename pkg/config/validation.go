package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Simplified validation for essential configuration only

type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

func (e ValidationError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("validation failed for field '%s': %s (value: %s)", e.Field, e.Message, e.Value)
	}
	return fmt.Sprintf("validation failed for field '%s': %s", e.Field, e.Message)
}

type Validator struct {
	errors []ValidationError
}

func NewValidator() *Validator {
	return &Validator{
		errors: make([]ValidationError, 0),
	}
}

func (v *Validator) AddError(field, message string, value ...string) {
	err := ValidationError{
		Field:   field,
		Message: message,
	}
	if len(value) > 0 {
		err.Value = value[0]
	}
	v.errors = append(v.errors, err)
}

func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

func (v *Validator) GetErrors() []ValidationError {
	return v.errors
}

func (v *Validator) Error() error {
	if !v.HasErrors() {
		return nil
	}

	var msgs []string
	for _, err := range v.errors {
		msgs = append(msgs, err.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}

func (m *Manager) ValidateConfiguration() error {
	validator := NewValidator()

	m.validateServerConfig(validator)
	m.validateDatabaseConfig(validator)
	m.validateSessionConfig(validator)
	m.validateDeploymentConfig(validator)

	return validator.Error()
}

func (m *Manager) validateServerConfig(v *Validator) {
	config := m.config

	// Validate Auth server
	if host, ok := config.Server.Auth.Host.Get(); ok {
		if !m.isValidHost(host) {
			v.AddError("server.auth.host", "invalid host address", host)
		}
	} else {
		v.AddError("server.auth.host", "host is required")
	}

	if port, ok := config.Server.Auth.Port.Get(); ok {
		if !m.isValidPort(port) {
			v.AddError("server.auth.port", "invalid port number", strconv.Itoa(port))
		}
	} else {
		v.AddError("server.auth.port", "port is required")
	}

	// Validate Control server
	if host, ok := config.Server.Control.Host.Get(); ok {
		if !m.isValidHost(host) {
			v.AddError("server.control.host", "invalid host address", host)
		}
	} else {
		v.AddError("server.control.host", "control server host is required")
	}

	if port, ok := config.Server.Control.Port.Get(); ok {
		if !m.isValidPort(port) {
			v.AddError("server.control.port", "invalid port number", strconv.Itoa(port))
		}
	} else {
		v.AddError("server.control.port", "control server port is required")
	}

	// Validate TLS configuration
	if enabled, ok := config.Server.Control.TLS.Enabled.Get(); ok && enabled {
		if certFile, ok := config.Server.Control.TLS.CertFile.Get(); ok {
			if !m.fileExists(certFile) {
				v.AddError("server.control.tls.cert_file", "certificate file does not exist", certFile)
			}
		} else {
			v.AddError("server.control.tls.cert_file", "certificate file is required when TLS is enabled")
		}

		if keyFile, ok := config.Server.Control.TLS.KeyFile.Get(); ok {
			if !m.fileExists(keyFile) {
				v.AddError("server.control.tls.key_file", "key file does not exist", keyFile)
			}
		} else {
			v.AddError("server.control.tls.key_file", "key file is required when TLS is enabled")
		}

		if caFile, ok := config.Server.Control.TLS.CAFile.Get(); ok {
			if !m.fileExists(caFile) {
				v.AddError("server.control.tls.ca_file", "CA file does not exist", caFile)
			}
		} else {
			v.AddError("server.control.tls.ca_file", "CA file is required when TLS is enabled")
		}
	}
}

func (m *Manager) validateDatabaseConfig(v *Validator) {
	config := m.config

	// Validate PostgreSQL configuration
	if host, ok := config.Database.Postgres.Host.Get(); ok {
		if !m.isValidHost(host) {
			v.AddError("database.postgres.host", "invalid host address", host)
		}
	} else {
		v.AddError("database.postgres.host", "PostgreSQL host is required")
	}

	if port, ok := config.Database.Postgres.Port.Get(); ok {
		if !m.isValidPort(port) {
			v.AddError("database.postgres.port", "invalid port number", strconv.Itoa(port))
		}
	} else {
		v.AddError("database.postgres.port", "PostgreSQL port is required")
	}

	if database, ok := config.Database.Postgres.Database.Get(); ok {
		if database == "" {
			v.AddError("database.postgres.database", "database name cannot be empty")
		}
	} else {
		v.AddError("database.postgres.database", "database name is required")
	}

	if username, ok := config.Database.Postgres.Username.Get(); ok {
		if username == "" {
			v.AddError("database.postgres.username", "username cannot be empty")
		}
	} else {
		v.AddError("database.postgres.username", "username is required")
	}

	if password, ok := config.Database.Postgres.Password.Get(); ok {
		if password == "" {
			v.AddError("database.postgres.password", "password cannot be empty")
		}
	} else {
		v.AddError("database.postgres.password", "password is required")
	}

	// Validate Redis configuration
	if host, ok := config.Database.Redis.Host.Get(); ok {
		if !m.isValidHost(host) {
			v.AddError("database.redis.host", "invalid host address", host)
		}
	} else {
		v.AddError("database.redis.host", "Redis host is required")
	}

	if port, ok := config.Database.Redis.Port.Get(); ok {
		if !m.isValidPort(port) {
			v.AddError("database.redis.port", "invalid port number", strconv.Itoa(port))
		}
	} else {
		v.AddError("database.redis.port", "Redis port is required")
	}
}

func (m *Manager) validateSessionConfig(v *Validator) {
	config := m.config

	// Validate SameSite values
	if sameSite := config.Session.SameSite.GetOrDefault(); sameSite != "" {
		validValues := []string{"Strict", "Lax", "None"}
		if !m.stringInSlice(sameSite, validValues) {
			v.AddError("session.same_site", "invalid SameSite value", sameSite)
		}
	}
}

func (m *Manager) validateDeploymentConfig(v *Validator) {
	config := m.config

	// Validate environment
	if env, ok := config.Deployment.Environment.Get(); ok {
		validEnvs := []Environment{EnvDevelopment, EnvStaging, EnvProduction}
		found := false
		for _, validEnv := range validEnvs {
			if env == validEnv {
				found = true
				break
			}
		}
		if !found {
			v.AddError("deployment.environment", "invalid environment", string(env))
		}
	}
}

// Helper validation methods
func (m *Manager) isValidHost(host string) bool {
	if host == "localhost" || host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	// Simple hostname validation
	return true // Simplified for now
}

func (m *Manager) isValidPort(port int) bool {
	return port > 0 && port <= 65535
}

func (m *Manager) fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func (m *Manager) stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}