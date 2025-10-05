package control

import "akashic/akashic/pkg/config"

const redactedPlaceholder string = "[REDACTED]"

// SanitizeConfig removes sensitive information from the configuration
func SanitizeConfig(cfg *config.Config) map[string]any {
	sanitized := make(map[string]any)

	// Server configuration (safe to expose)
	sanitized["server"] = map[string]any{
		"auth": map[string]any{
			"host": cfg.Server.Auth.Host,
			"port": cfg.Server.Auth.Port,
		},
		"control": map[string]any{
			"host": cfg.Server.Control.Host,
			"port": cfg.Server.Control.Port,
			"tls": map[string]any{
				"enabled":              cfg.Server.Control.TLS.Enabled,
				"client_auth_required": cfg.Server.Control.TLS.ClientAuthRequired,
				"cert_file":            cfg.Server.Control.TLS.CertFile,
				"key_file":             redactedPlaceholder, // Path shown but not content
				"ca_file":              cfg.Server.Control.TLS.CAFile,
			},
		},
	}

	// Database configuration (hide passwords)
	sanitized["database"] = map[string]any{
		"postgres": map[string]any{
			"host":                 cfg.Database.Postgres.Host,
			"port":                 cfg.Database.Postgres.Port,
			"database":             cfg.Database.Postgres.Database,
			"username":             cfg.Database.Postgres.Username,
			"password":             redactedPlaceholder,
			"ssl_mode":             cfg.Database.Postgres.SSLMode,
			"max_connections":      cfg.Database.Postgres.MaxConnections,
			"max_idle_connections": cfg.Database.Postgres.MaxIdleConnections,
			"connection_lifetime":  cfg.Database.Postgres.ConnectionLifetime.String(),
		},
		"redis": map[string]any{
			"host":        cfg.Database.Redis.Host,
			"port":        cfg.Database.Redis.Port,
			"password":    redactedPlaceholder,
			"db":          cfg.Database.Redis.DB,
			"pool_size":   cfg.Database.Redis.PoolSize,
			"session_ttl": cfg.Database.Redis.SessionTTL.String(),
			"cache_ttl":   cfg.Database.Redis.CacheTTL.String(),
		},
	}

	// Session configuration (safe to expose)
	sanitized["session"] = map[string]any{
		"timeout":        cfg.Session.Timeout.String(),
		"secure_cookies": cfg.Session.SecureCookies,
		"same_site":      cfg.Session.SameSite,
		"cookie_name":    cfg.Session.CookieName,
		"cookie_path":    cfg.Session.CookiePath,
	}

	// Logging configuration (hide Loki credentials)
	sanitized["logging"] = map[string]any{
		"service_name": cfg.Logging.ServiceName,
		"environment":  cfg.Logging.Environment,
		"app": map[string]any{
			"enabled":          cfg.Logging.App.Enabled,
			"show_caller":      cfg.Logging.App.ShowCaller,
			"show_stacktrace":  cfg.Logging.App.ShowStacktrace,
			"stacktrace_level": cfg.Logging.App.StacktraceLevel,
			"sinks_count":      len(cfg.Logging.App.Sinks),
		},
		"security": map[string]any{
			"enabled":          cfg.Logging.Security.Enabled,
			"show_caller":      cfg.Logging.Security.ShowCaller,
			"show_stacktrace":  cfg.Logging.Security.ShowStacktrace,
			"stacktrace_level": cfg.Logging.Security.StacktraceLevel,
			"sinks_count":      len(cfg.Logging.Security.Sinks),
		},
		"audit": map[string]any{
			"enabled":          cfg.Logging.Audit.Enabled,
			"show_caller":      cfg.Logging.Audit.ShowCaller,
			"show_stacktrace":  cfg.Logging.Audit.ShowStacktrace,
			"stacktrace_level": cfg.Logging.Audit.StacktraceLevel,
			"sinks_count":      len(cfg.Logging.Audit.Sinks),
		},
	}

	// Deployment configuration (safe to expose)
	sanitized["deployment"] = map[string]any{
		"environment": cfg.Deployment.Environment.String(),
	}

	return sanitized
}
