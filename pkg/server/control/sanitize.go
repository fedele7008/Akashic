package control

import (
	"akashic/akashic/pkg/config"
	"fmt"
)

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
				"key_file":             cfg.Server.Control.TLS.KeyFile,
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
		"service_name":       cfg.Logging.ServiceName,
		"environment":        cfg.Logging.Environment,
		"force_audit_append": cfg.Logging.ForceAuditAppend,
		"app": map[string]any{
			"enabled":          cfg.Logging.App.Enabled,
			"show_caller":      cfg.Logging.App.ShowCaller,
			"show_stacktrace":  cfg.Logging.App.ShowStacktrace,
			"stacktrace_level": cfg.Logging.App.StacktraceLevel,
			"sinks":            getSanitizedSinks(&cfg.Logging.App),
		},
		"security": map[string]any{
			"enabled":          cfg.Logging.Security.Enabled,
			"show_caller":      cfg.Logging.Security.ShowCaller,
			"show_stacktrace":  cfg.Logging.Security.ShowStacktrace,
			"stacktrace_level": cfg.Logging.Security.StacktraceLevel,
			"sinks":            getSanitizedSinks(&cfg.Logging.Security),
		},
		"audit": map[string]any{
			"enabled":          cfg.Logging.Audit.Enabled,
			"show_caller":      cfg.Logging.Audit.ShowCaller,
			"show_stacktrace":  cfg.Logging.Audit.ShowStacktrace,
			"stacktrace_level": cfg.Logging.Audit.StacktraceLevel,
			"sinks":            getSanitizedSinks(&cfg.Logging.Audit),
		},
		"encoder": map[string]any{
			"timestamp_key":  cfg.Logging.EncoderConfig.TimestampKey,
			"time_format":    cfg.Logging.EncoderConfig.TimeFormatKey,
			"level_key":      cfg.Logging.EncoderConfig.LevelKey,
			"name_key":       cfg.Logging.EncoderConfig.NameKey,
			"caller_key":     cfg.Logging.EncoderConfig.CallerKey,
			"message_key":    cfg.Logging.EncoderConfig.MessageKey,
			"stacktrace_key": cfg.Logging.EncoderConfig.StacktraceKey,
		},
	}

	// Deployment configuration (safe to expose)
	sanitized["deployment"] = map[string]any{
		"environment": cfg.Deployment.Environment.String(),
	}

	// Middleware configuration (safe to expose)
	sanitized["middleware"] = map[string]any{
		"auth": map[string]any{
			"security_headers": map[string]any{
				"x_frame_options":         cfg.Middleware.Auth.SecurityHeaders.XFrameOptions,
				"x_xss_protection":        cfg.Middleware.Auth.SecurityHeaders.XSSProtection,
				"hsts_max_age":            cfg.Middleware.Auth.SecurityHeaders.HSTSMaxAge,
				"hsts_include_subdomains": cfg.Middleware.Auth.SecurityHeaders.HSTSIncludeSubDomains,
				"hsts_preload":            cfg.Middleware.Auth.SecurityHeaders.HSTSPreload,
				"content_security_policy": cfg.Middleware.Auth.SecurityHeaders.ContentSecurityPolicy,
				"remove_server_header":    cfg.Middleware.Auth.SecurityHeaders.RemoveServerHeader,
			},
			"cors": map[string]any{
				"enabled":           cfg.Middleware.Auth.CORS.Enabled,
				"allowed_origins":   cfg.Middleware.Auth.CORS.AllowedOrigins,
				"allowed_methods":   cfg.Middleware.Auth.CORS.AllowedMethods,
				"allowed_headers":   cfg.Middleware.Auth.CORS.AllowedHeaders,
				"exposed_headers":   cfg.Middleware.Auth.CORS.ExposedHeaders,
				"allow_credentials": cfg.Middleware.Auth.CORS.AllowCredentials,
				"max_age":           cfg.Middleware.Auth.CORS.MaxAge,
			},
			"rate_limit": map[string]any{
				"enabled":             cfg.Middleware.Auth.RateLimit.Enabled,
				"requests_per_window": cfg.Middleware.Auth.RateLimit.RequestsPerWindow,
				"window_duration":     cfg.Middleware.Auth.RateLimit.WindowDuration.String(),
			},
			"logging": map[string]any{
				"skip_paths": cfg.Middleware.Auth.Logging.SkipPaths,
			},
			"max_request_size_bytes": cfg.Middleware.Auth.MaxRequestSizeBytes,
			"request_timeout":        cfg.Middleware.Auth.RequestTimeout.String(),
		},
		"control": map[string]any{
			"security_headers": map[string]any{
				"x_frame_options":         cfg.Middleware.Control.SecurityHeaders.XFrameOptions,
				"x_xss_protection":        cfg.Middleware.Control.SecurityHeaders.XSSProtection,
				"hsts_max_age":            cfg.Middleware.Control.SecurityHeaders.HSTSMaxAge,
				"hsts_include_subdomains": cfg.Middleware.Control.SecurityHeaders.HSTSIncludeSubDomains,
				"hsts_preload":            cfg.Middleware.Control.SecurityHeaders.HSTSPreload,
				"content_security_policy": cfg.Middleware.Control.SecurityHeaders.ContentSecurityPolicy,
				"remove_server_header":    cfg.Middleware.Control.SecurityHeaders.RemoveServerHeader,
			},
			"ip_allowlist": map[string]any{
				"enabled":        cfg.Middleware.Control.IPAllowlist.Enabled,
				"ips":            cfg.Middleware.Control.IPAllowlist.AllowedIPs,
				"allow_loopback": cfg.Middleware.Control.IPAllowlist.AllowLoopback,
				"trust_proxy":    cfg.Middleware.Control.IPAllowlist.TrustProxy,
			},
			"cors": map[string]any{
				"enabled":           cfg.Middleware.Control.CORS.Enabled,
				"allowed_origins":   cfg.Middleware.Control.CORS.AllowedOrigins,
				"allowed_methods":   cfg.Middleware.Control.CORS.AllowedMethods,
				"allowed_headers":   cfg.Middleware.Control.CORS.AllowedHeaders,
				"exposed_headers":   cfg.Middleware.Control.CORS.ExposedHeaders,
				"allow_credentials": cfg.Middleware.Control.CORS.AllowCredentials,
				"max_age":           cfg.Middleware.Control.CORS.MaxAge,
			},
			"rate_limit": map[string]any{
				"enabled":             cfg.Middleware.Control.RateLimit.Enabled,
				"requests_per_window": cfg.Middleware.Control.RateLimit.RequestsPerWindow,
				"window_duration":     cfg.Middleware.Control.RateLimit.WindowDuration.String(),
			},
			"logging": map[string]any{
				"skip_paths": cfg.Middleware.Control.Logging.SkipPaths,
			},
			"max_request_size_bytes": cfg.Middleware.Control.MaxRequestSizeBytes,
			"request_timeout":        cfg.Middleware.Control.RequestTimeout.String(),
		},
	}

	// Bootstrap configuration (hide passwords)
	sanitized["bootstrap"] = map[string]any{
		"token_ttl": cfg.Bootstrap.TokenTTL.String(),
		"password": map[string]any{
			"min_length":        cfg.Bootstrap.Password.MinLength,
			"require_uppercase": cfg.Bootstrap.Password.RequireUppercase,
			"require_number":    cfg.Bootstrap.Password.RequireNumber,
			"require_special":   cfg.Bootstrap.Password.RequireSpecial,
		},
	}

	// LDAP configuration (hide credentials)
	sanitized["ldap"] = map[string]any{
		"host":               cfg.LDAP.Host,
		"port":               cfg.LDAP.Port,
		"base_dn":            cfg.LDAP.BaseDN,
		"bind_dn":            cfg.LDAP.BindDN,
		"bind_password":      redactedPlaceholder,
		"use_tls":            cfg.LDAP.UseTLS,
		"tls_skip_verify":    cfg.LDAP.TLSSkipVerify,
		"user_search_base":   cfg.LDAP.UserSearchBase,
		"user_search_filter": cfg.LDAP.UserSearchFilter,
		"user_object_class":  cfg.LDAP.UserObjectClass,
		"username_attr":      cfg.LDAP.UsernameAttr,
		"email_attr":         cfg.LDAP.EmailAttr,
		"display_name_attr":  cfg.LDAP.DisplayNameAttr,
	}

	return sanitized
}

func getSanitizedSinks(chCfg *config.ChannelConfig) []map[string]any {
	sinksCfg := make([]map[string]any, len(chCfg.Sinks))
	for i, sink := range chCfg.Sinks {
		sinksCfg[i] = map[string]any{
			"type":    sink.Type.String(),
			"enabled": sink.Enabled,
			"level":   sink.Level.String(),
			"format":  sink.Format.String(),
		}
		if sink.Type == config.SinkLoki {
			sinksCfg[i]["format"] = fmt.Sprintf("%v (ignored and fixed to json)", sinksCfg[i]["format"])
			sinksCfg[i]["loki_url"] = redactedPlaceholder
			sinksCfg[i]["basic_auth_user"] = redactedPlaceholder
			sinksCfg[i]["basic_auth_pass"] = redactedPlaceholder
			sinksCfg[i]["loki_labels"] = chCfg.Sinks[i].LokiLabels
			sinksCfg[i]["batch_size"] = chCfg.Sinks[i].BatchSize
			sinksCfg[i]["batch_flush_period_ms"] = chCfg.Sinks[i].BatchFlushPeriodMs
			sinksCfg[i]["retry_max_count"] = chCfg.Sinks[i].RetryMaxCount
			sinksCfg[i]["retry_min_backoff_ms"] = chCfg.Sinks[i].RetryMinBackoffMs
			sinksCfg[i]["retry_max_backoff_ms"] = chCfg.Sinks[i].RetryMaxBackoffMs
			sinksCfg[i]["compress"] = chCfg.Sinks[i].Compress
			sinksCfg[i]["breaker_max_retries"] = chCfg.Sinks[i].BreakerMaxRetries
			sinksCfg[i]["breaker_cooldown_ms"] = chCfg.Sinks[i].BreakerCooldownMs
			sinksCfg[i]["client_timeout_ms"] = chCfg.Sinks[i].ClientTimeoutMs
		}
		if sink.Type == config.SinkFile {
			sinksCfg[i]["file_path"] = chCfg.Sinks[i].FilePath
			sinksCfg[i]["file_mode"] = chCfg.Sinks[i].FileMode.String()
			sinksCfg[i]["max_size_mb"] = chCfg.Sinks[i].MaxSizeMB
			sinksCfg[i]["max_backups"] = chCfg.Sinks[i].MaxBackups
		}
	}
	return sinksCfg
}
