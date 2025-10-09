package config

import (
	"time"

	"github.com/spf13/viper"
)

const (
	// Viper defaults
	DefaultConfigFileName = "config"
	DefaultConfigFileType = "yaml"

	// Server defaults
	DefaultAuthHost = "0.0.0.0"
	DefaultAuthPort = 8080

	// Control server defaults
	DefaultControlHost        = "127.0.0.1"
	DefaultControlPort        = 8081
	DefaultTLSEnabled         = true
	DefaultCertFile           = "./certs/servers/control.crt"
	DefaultKeyFile            = "./certs/servers/control.key"
	DefaultCAFile             = "./certs/ca/ca.crt"
	DefaultClientAuthRequired = true

	// Database defaults - PostgreSQL
	DefaultPostgresHost               = "localhost"
	DefaultPostgresPort               = 5432
	DefaultPostgresDatabase           = "akashic"
	DefaultPostgresUsername           = "" // Empty - must be set via env var or config
	DefaultPostgresPassword           = "" // Empty - must be set via env var or config
	DefaultPostgresSSLMode            = "disable" // disable for dev, require for production
	DefaultPostgresMaxConnections     = 100
	DefaultPostgresMaxIdleConnections = 10
	DefaultPostgresConnectionLifetime = 1 * time.Hour

	// Database defaults - Redis
	DefaultRedisHost       = "localhost"
	DefaultRedisPort       = 6379
	DefaultRedisPassword   = "" // Empty - Redis can run without auth in dev
	DefaultRedisDB         = 0
	DefaultRedisPoolSize   = 10
	DefaultRedisSessionTTL = 24 * time.Hour
	DefaultRedisCacheTTL   = 1 * time.Hour

	// Session defaults
	DefaultSessionTimeout = 30 * time.Minute
	DefaultSecureCookies  = true
	DefaultSameSite       = "Strict"
	DefaultCookieName     = "akashic_session"
	DefaultCookiePath     = "/"

	// Logging defaults
	DefaultLoggingServiceName = "akashic"

	// Logging sink defaults
	DefaultLogLevel                  = LevelInfo
	DefaultLogFormat                 = FormatJSON
	DefaultFileMode                  = FileRolling
	DefaultMaxSizeMB          int    = 100
	DefaultMaxBackups         int    = 3
	DefaultBasicAuthUser      string = ""
	DefaultBasicAuthPass      string = ""
	DefaultBatchSize          int    = 100
	DefaultBatchFlushPeriodMs int    = 1000
	DefaultRetryMaxCount      int    = 5
	DefaultRetryMinBackoffMs  int    = 200
	DefaultRetryMaxBackoffMs  int    = 2000
	DefaultCompress           bool   = true
	DefaultBreakerMaxRetries  int    = 1
	DefaultBreakerCooldownMs  int    = 5000
	DefaultClientTimeoutMs    int    = 10000

	// Logging channel defaults
	DefaultChannelEnabled  bool = true
	DefaultShowCaller      bool = true
	DefaultShowStacktrace  bool = true
	DefaultStacktraceLevel      = LevelError

	// Logging encoder defaults
	DefaultTimestampKey  = "timestamp"
	DefaultTimeFormat    = time.UnixDate
	DefaultLogLevelKey   = "level"
	DefaultNameKey       = "logging"
	DefaultCallerKey     = "caller"
	DefaultMessageKey    = "message"
	DefaultStacktraceKey = "stacktrace"

	// Logging config defaults
	DefaultForceAuditAppend bool = true

	// Deployment defaults
	DefaultEnvironment = EnvDevelopment

	// Bootstrap defaults
	DefaultBootstrapTokenTTL          = 1 * time.Hour
	DefaultBootstrapPasswordMinLength = 12
	DefaultBootstrapRequireUppercase  = true
	DefaultBootstrapRequireNumber     = true
	DefaultBootstrapRequireSpecial    = true

	// LDAP server defaults
	DefaultLDAPHost              = "ldap" // Docker service name
	DefaultLDAPPort              = 389
	DefaultLDAPBaseDN            = "dc=akashic,dc=local"
	DefaultLDAPBindDN            = "cn=admin,dc=akashic,dc=local"
	DefaultLDAPBindPassword      = "" // Must be set via env var
	DefaultLDAPUseTLS            = false
	DefaultLDAPTLSSkipVerify     = false
	DefaultLDAPUserSearchBase    = "ou=users,dc=akashic,dc=local"
	DefaultLDAPUserSearchFilter  = "(uid={username})"
	DefaultLDAPUserObjectClass   = "inetOrgPerson"
	DefaultLDAPUsernameAttr      = "uid"
	DefaultLDAPEmailAttr         = "mail"
	DefaultLDAPDisplayNameAttr   = "cn"

	// LDAP RBAC defaults
	DefaultLDAPRBACRootGroup     = "cn=akashic-root,ou=groups,dc=akashic,dc=local"
	DefaultLDAPRBACAdminGroup    = "cn=akashic-admins,ou=groups,dc=akashic,dc=local"
	DefaultLDAPRBACUserGroup     = "cn=akashic-users,ou=groups,dc=akashic,dc=local"
	DefaultLDAPRBACDefaultType   = "user"

	// LDAP Deprovisioning defaults
	DefaultLDAPDeprovisioningEnabled              = true
	DefaultLDAPDeprovisioningSyncInterval         = 1 * time.Hour
	DefaultLDAPDeprovisioningRootDeletionThreshold  = 0 * time.Second // Immediate
	DefaultLDAPDeprovisioningAdminDeletionThreshold = 720 * time.Hour  // 30 days
	DefaultLDAPDeprovisioningUserDeletionThreshold  = 2160 * time.Hour // 90 days

	// PKI defaults
	DefaultPKIEnabled                    = true
	DefaultPKICertsDir                   = "./certs"
	DefaultPKIKeyType                    = "rsa"
	DefaultPKIRSAKeySize                 = 2048
	DefaultPKIECDSACurve                 = "P-256"
	DefaultPKICAValidityYears            = 10
	DefaultPKICACommonName               = "Akashic Self-Signed CA"
	DefaultPKICAOrganization             = "Akashic"
	DefaultPKICACountry                  = "US"
	DefaultPKIServerValidityDays         = 365
	DefaultPKIClientValidityDays         = 365

	// PKI file paths
	DefaultPKICACertFile                 = "certs/ca/ca.crt"
	DefaultPKICAKeyFile                  = "certs/ca/ca.key"
	DefaultPKIControlServerCertFile      = "certs/servers/control.crt"
	DefaultPKIControlServerKeyFile       = "certs/servers/control.key"
	DefaultPKIAuthServerCertFile         = "certs/servers/auth.crt"
	DefaultPKIAuthServerKeyFile          = "certs/servers/auth.key"
	DefaultPKILDAPServerCertFile         = "certs/servers/ldap.crt"
	DefaultPKILDAPServerKeyFile          = "certs/servers/ldap.key"
	DefaultPKICLIClientCertFile          = "certs/clients/cli.crt"
	DefaultPKICLIClientKeyFile           = "certs/clients/cli.key"
	DefaultPKIBFFClientCertFile          = "certs/clients/bff.crt"
	DefaultPKIBFFClientKeyFile           = "certs/clients/bff.key"

	// Middleware defaults - Auth Server
	DefaultAuthMaxRequestSizeBytes int64         = 5 * 1024 * 1024 // 5MB
	DefaultAuthRequestTimeout      time.Duration = 30 * time.Second
	DefaultAuthCORSMaxAge                        = 3600 // 1 hour

	// Middleware defaults - Control Server
	DefaultControlMaxRequestSizeBytes int64         = 1 * 1024 * 1024 // 1MB
	DefaultControlRequestTimeout      time.Duration = 60 * time.Second
	DefaultControlCORSMaxAge                        = 7200 // 2 hours

	// Rate limit defaults
	DefaultRateLimitRequestsPerWindow = 100
	DefaultRateLimitWindowDuration    = 1 * time.Minute

	// IP allowlist defaults
	DefaultIPAllowLoopback = true
	DefaultIPTrustProxy    = false
)

// setDefaults sets default values in viper before unmarshaling
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.auth.host", DefaultAuthHost)
	v.SetDefault("server.auth.port", DefaultAuthPort)

	// Control server defaults
	v.SetDefault("server.control.host", DefaultControlHost)
	v.SetDefault("server.control.port", DefaultControlPort)
	v.SetDefault("server.control.tls.enabled", DefaultTLSEnabled)
	v.SetDefault("server.control.tls.cert_file", DefaultCertFile)
	v.SetDefault("server.control.tls.key_file", DefaultKeyFile)
	v.SetDefault("server.control.tls.ca_file", DefaultCAFile)
	v.SetDefault("server.control.tls.client_auth_required", DefaultClientAuthRequired)

	// Database defaults
	v.SetDefault("database.postgres.host", DefaultPostgresHost)
	v.SetDefault("database.postgres.port", DefaultPostgresPort)
	v.SetDefault("database.postgres.database", DefaultPostgresDatabase)
	v.SetDefault("database.postgres.username", DefaultPostgresUsername)
	v.SetDefault("database.postgres.password", DefaultPostgresPassword)
	v.SetDefault("database.postgres.ssl_mode", DefaultPostgresSSLMode)
	v.SetDefault("database.postgres.max_connections", DefaultPostgresMaxConnections)
	v.SetDefault("database.postgres.max_idle_connections", DefaultPostgresMaxIdleConnections)
	v.SetDefault("database.postgres.connection_lifetime", DefaultPostgresConnectionLifetime)

	v.SetDefault("database.redis.host", DefaultRedisHost)
	v.SetDefault("database.redis.port", DefaultRedisPort)
	v.SetDefault("database.redis.password", DefaultRedisPassword)
	v.SetDefault("database.redis.db", DefaultRedisDB)
	v.SetDefault("database.redis.pool_size", DefaultRedisPoolSize)
	v.SetDefault("database.redis.session_ttl", DefaultRedisSessionTTL)
	v.SetDefault("database.redis.cache_ttl", DefaultRedisCacheTTL)

	// Session defaults
	v.SetDefault("session.timeout", DefaultSessionTimeout)
	v.SetDefault("session.secure_cookies", DefaultSecureCookies)
	v.SetDefault("session.same_site", DefaultSameSite)
	v.SetDefault("session.cookie_name", DefaultCookieName)
	v.SetDefault("session.cookie_path", DefaultCookiePath)

	// Logging defaults
	v.SetDefault("logging.service_name", DefaultLoggingServiceName)
	v.SetDefault("logging.environment", DefaultEnvironment.String())
	v.SetDefault("logging.force_audit_append", DefaultForceAuditAppend)

	// Logging encoder defaults
	v.SetDefault("logging.encoder.timestamp_key", DefaultTimestampKey)
	v.SetDefault("logging.encoder.time_format", DefaultTimeFormat)
	v.SetDefault("logging.encoder.level_key", DefaultLogLevelKey)
	v.SetDefault("logging.encoder.name_key", DefaultNameKey)
	v.SetDefault("logging.encoder.caller_key", DefaultCallerKey)
	v.SetDefault("logging.encoder.message_key", DefaultMessageKey)
	v.SetDefault("logging.encoder.stacktrace_key", DefaultStacktraceKey)

	// Logging channel defaults
	v.SetDefault("logging.app.enabled", DefaultChannelEnabled)
	v.SetDefault("logging.app.show_caller", DefaultShowCaller)
	v.SetDefault("logging.app.show_stacktrace", DefaultShowStacktrace)
	v.SetDefault("logging.app.stacktrace_level", DefaultStacktraceLevel)

	v.SetDefault("logging.security.enabled", DefaultChannelEnabled)
	v.SetDefault("logging.security.show_caller", DefaultShowCaller)
	v.SetDefault("logging.security.show_stacktrace", DefaultShowStacktrace)
	v.SetDefault("logging.security.stacktrace_level", DefaultStacktraceLevel)

	v.SetDefault("logging.audit.enabled", DefaultChannelEnabled)
	v.SetDefault("logging.audit.show_caller", DefaultShowCaller)
	v.SetDefault("logging.audit.show_stacktrace", DefaultShowStacktrace)
	v.SetDefault("logging.audit.stacktrace_level", DefaultStacktraceLevel)

	// Deployment defaults
	v.SetDefault("deployment.environment", DefaultEnvironment.String())

	// Bootstrap defaults
	v.SetDefault("bootstrap.token_ttl", DefaultBootstrapTokenTTL)
	v.SetDefault("bootstrap.password.min_length", DefaultBootstrapPasswordMinLength)
	v.SetDefault("bootstrap.password.require_uppercase", DefaultBootstrapRequireUppercase)
	v.SetDefault("bootstrap.password.require_number", DefaultBootstrapRequireNumber)
	v.SetDefault("bootstrap.password.require_special", DefaultBootstrapRequireSpecial)

	// LDAP server defaults
	v.SetDefault("ldap.host", DefaultLDAPHost)
	v.SetDefault("ldap.port", DefaultLDAPPort)
	v.SetDefault("ldap.base_dn", DefaultLDAPBaseDN)
	v.SetDefault("ldap.bind_dn", DefaultLDAPBindDN)
	v.SetDefault("ldap.bind_password", DefaultLDAPBindPassword)
	v.SetDefault("ldap.use_tls", DefaultLDAPUseTLS)
	v.SetDefault("ldap.tls_skip_verify", DefaultLDAPTLSSkipVerify)
	v.SetDefault("ldap.user_search_base", DefaultLDAPUserSearchBase)
	v.SetDefault("ldap.user_search_filter", DefaultLDAPUserSearchFilter)
	v.SetDefault("ldap.user_object_class", DefaultLDAPUserObjectClass)
	v.SetDefault("ldap.username_attr", DefaultLDAPUsernameAttr)
	v.SetDefault("ldap.email_attr", DefaultLDAPEmailAttr)
	v.SetDefault("ldap.display_name_attr", DefaultLDAPDisplayNameAttr)

	// LDAP RBAC defaults
	v.SetDefault("ldap.rbac.root_group", DefaultLDAPRBACRootGroup)
	v.SetDefault("ldap.rbac.admin_group", DefaultLDAPRBACAdminGroup)
	v.SetDefault("ldap.rbac.user_group", DefaultLDAPRBACUserGroup)
	v.SetDefault("ldap.rbac.default_type", DefaultLDAPRBACDefaultType)

	// LDAP Deprovisioning defaults
	v.SetDefault("ldap.deprovisioning.enabled", DefaultLDAPDeprovisioningEnabled)
	v.SetDefault("ldap.deprovisioning.sync_interval", DefaultLDAPDeprovisioningSyncInterval)
	v.SetDefault("ldap.deprovisioning.root_deletion_threshold", DefaultLDAPDeprovisioningRootDeletionThreshold)
	v.SetDefault("ldap.deprovisioning.admin_deletion_threshold", DefaultLDAPDeprovisioningAdminDeletionThreshold)
	v.SetDefault("ldap.deprovisioning.user_deletion_threshold", DefaultLDAPDeprovisioningUserDeletionThreshold)

	// PKI defaults
	v.SetDefault("pki.enabled", DefaultPKIEnabled)
	v.SetDefault("pki.certs_dir", DefaultPKICertsDir)
	v.SetDefault("pki.key_type", DefaultPKIKeyType)
	v.SetDefault("pki.rsa_key_size", DefaultPKIRSAKeySize)
	v.SetDefault("pki.ecdsa_curve", DefaultPKIECDSACurve)

	// PKI CA defaults
	v.SetDefault("pki.ca.cert_file", DefaultPKICACertFile)
	v.SetDefault("pki.ca.key_file", DefaultPKICAKeyFile)
	v.SetDefault("pki.ca.validity_years", DefaultPKICAValidityYears)
	v.SetDefault("pki.ca.common_name", DefaultPKICACommonName)
	v.SetDefault("pki.ca.organization", DefaultPKICAOrganization)
	v.SetDefault("pki.ca.country", DefaultPKICACountry)

	// PKI server defaults
	v.SetDefault("pki.servers.default_validity_days", DefaultPKIServerValidityDays)
	v.SetDefault("pki.servers.control.cert_file", DefaultPKIControlServerCertFile)
	v.SetDefault("pki.servers.control.key_file", DefaultPKIControlServerKeyFile)
	v.SetDefault("pki.servers.control.dns_names", []string{"localhost", "control.akashic.local"})
	v.SetDefault("pki.servers.control.ip_addresses", []string{"127.0.0.1"})
	v.SetDefault("pki.servers.auth.cert_file", DefaultPKIAuthServerCertFile)
	v.SetDefault("pki.servers.auth.key_file", DefaultPKIAuthServerKeyFile)
	v.SetDefault("pki.servers.auth.dns_names", []string{"localhost", "auth.akashic.local"})
	v.SetDefault("pki.servers.auth.ip_addresses", []string{"0.0.0.0"})
	v.SetDefault("pki.servers.ldap.cert_file", DefaultPKILDAPServerCertFile)
	v.SetDefault("pki.servers.ldap.key_file", DefaultPKILDAPServerKeyFile)
	v.SetDefault("pki.servers.ldap.dns_names", []string{"ldap", "ldap.akashic.local"})

	// PKI client defaults
	v.SetDefault("pki.clients.default_validity_days", DefaultPKIClientValidityDays)
	v.SetDefault("pki.clients.cli.cert_file", DefaultPKICLIClientCertFile)
	v.SetDefault("pki.clients.cli.key_file", DefaultPKICLIClientKeyFile)
	v.SetDefault("pki.clients.cli.common_name", "Akashic CLI Client")
	v.SetDefault("pki.clients.bff.cert_file", DefaultPKIBFFClientCertFile)
	v.SetDefault("pki.clients.bff.key_file", DefaultPKIBFFClientKeyFile)
	v.SetDefault("pki.clients.bff.common_name", "Akashic BFF Client")

	// Middleware defaults - Auth Server
	// Security headers
	v.SetDefault("middleware.auth.security_headers.x_frame_options", "DENY")
	v.SetDefault("middleware.auth.security_headers.x_xss_protection", "1; mode=block")
	v.SetDefault("middleware.auth.security_headers.hsts_max_age", 31536000)
	v.SetDefault("middleware.auth.security_headers.hsts_include_subdomains", true)
	v.SetDefault("middleware.auth.security_headers.hsts_preload", false)
	v.SetDefault("middleware.auth.security_headers.content_security_policy", "default-src 'self'")
	v.SetDefault("middleware.auth.security_headers.remove_server_header", true)
	// CORS
	v.SetDefault("middleware.auth.cors.enabled", false) // Disabled by default, must be configured
	v.SetDefault("middleware.auth.cors.allowed_origins", []string{})
	v.SetDefault("middleware.auth.cors.allowed_methods", []string{"GET", "POST", "OPTIONS"})
	v.SetDefault("middleware.auth.cors.allowed_headers", []string{"Content-Type", "Authorization", "X-Request-ID"})
	v.SetDefault("middleware.auth.cors.exposed_headers", []string{"X-Request-ID"})
	v.SetDefault("middleware.auth.cors.allow_credentials", true)
	v.SetDefault("middleware.auth.cors.max_age", DefaultAuthCORSMaxAge)
	// Rate limiting
	v.SetDefault("middleware.auth.rate_limit.enabled", false) // Disabled by default
	v.SetDefault("middleware.auth.rate_limit.requests_per_window", DefaultRateLimitRequestsPerWindow)
	v.SetDefault("middleware.auth.rate_limit.window_duration", DefaultRateLimitWindowDuration)
	// Logging
	v.SetDefault("middleware.auth.logging.skip_paths", []string{})
	// Request limits
	v.SetDefault("middleware.auth.max_request_size_bytes", DefaultAuthMaxRequestSizeBytes)
	v.SetDefault("middleware.auth.request_timeout", DefaultAuthRequestTimeout)

	// Middleware defaults - Control Server
	// Security headers
	v.SetDefault("middleware.control.security_headers.x_frame_options", "DENY")
	v.SetDefault("middleware.control.security_headers.x_xss_protection", "1; mode=block")
	v.SetDefault("middleware.control.security_headers.hsts_max_age", 31536000)
	v.SetDefault("middleware.control.security_headers.hsts_include_subdomains", true)
	v.SetDefault("middleware.control.security_headers.hsts_preload", false)
	v.SetDefault("middleware.control.security_headers.content_security_policy", "default-src 'self'")
	v.SetDefault("middleware.control.security_headers.remove_server_header", true)
	// IP allowlist
	v.SetDefault("middleware.control.ip_allowlist.enabled", false) // Disabled by default
	v.SetDefault("middleware.control.ip_allowlist.allowed_ips", []string{})
	v.SetDefault("middleware.control.ip_allowlist.allow_loopback", DefaultIPAllowLoopback)
	v.SetDefault("middleware.control.ip_allowlist.trust_proxy", DefaultIPTrustProxy)
	// CORS
	v.SetDefault("middleware.control.cors.enabled", false) // Disabled by default
	v.SetDefault("middleware.control.cors.allowed_origins", []string{})
	v.SetDefault("middleware.control.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("middleware.control.cors.allowed_headers", []string{"Content-Type", "Authorization", "X-Request-ID", "X-Client-Cert-DN"})
	v.SetDefault("middleware.control.cors.exposed_headers", []string{"X-Request-ID"})
	v.SetDefault("middleware.control.cors.allow_credentials", true)
	v.SetDefault("middleware.control.cors.max_age", DefaultControlCORSMaxAge)
	// Rate limiting
	v.SetDefault("middleware.control.rate_limit.enabled", false) // Disabled by default
	v.SetDefault("middleware.control.rate_limit.requests_per_window", DefaultRateLimitRequestsPerWindow)
	v.SetDefault("middleware.control.rate_limit.window_duration", DefaultRateLimitWindowDuration)
	// Logging
	v.SetDefault("middleware.control.logging.skip_paths", []string{"/health"})
	// Request limits
	v.SetDefault("middleware.control.max_request_size_bytes", DefaultControlMaxRequestSizeBytes)
	v.SetDefault("middleware.control.request_timeout", DefaultControlRequestTimeout)
}
