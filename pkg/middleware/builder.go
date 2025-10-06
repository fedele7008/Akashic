package middleware

import (
	"akashic/akashic/pkg/logging"
	"net/http"
	"time"
)

// ChainBuilder helps build middleware chains for different server types
type ChainBuilder struct {
	middlewares []Middleware
}

// NewChainBuilder creates a new middleware chain builder
func NewChainBuilder() *ChainBuilder {
	return &ChainBuilder{
		middlewares: make([]Middleware, 0),
	}
}

// Add adds a middleware to the chain
func (cb *ChainBuilder) Add(mw Middleware) *ChainBuilder {
	cb.middlewares = append(cb.middlewares, mw)
	return cb
}

// Build creates the final middleware chain
func (cb *ChainBuilder) Build() Middleware {
	return Chain(cb.middlewares...)
}

// Apply applies the middleware chain to a handler
func (cb *ChainBuilder) Apply(handler http.Handler) http.Handler {
	return cb.Build()(handler)
}

// AuthServerChain builds the standard middleware chain for Auth Server
func AuthServerChain(
	logger *logging.Logger,
	corsConfig *CORSConfig,
	rateLimitConfig *RateLimitConfig,
	sizeLimitConfig *SizeLimitConfig,
	timeoutConfig *TimeoutConfig,
) *ChainBuilder {
	builder := NewChainBuilder()

	// 1. Request ID (generate correlation ID)
	builder.Add(RequestID())

	// 2. Logging
	builder.Add(Logging(logger, &LoggingConfig{
		SkipPaths: map[string]bool{}, // Can skip /health if needed
	}))

	// 3. Recovery (catch panics from anything below)
	builder.Add(Recovery(logger))

	// 4. Security Headers
	builder.Add(SecurityHeaders(DefaultSecurityHeadersConfig()))

	// 5. CORS
	if corsConfig != nil {
		builder.Add(CORS(corsConfig))
	}

	// 6. Request Size Limit
	if sizeLimitConfig != nil {
		builder.Add(RequestSizeLimit(sizeLimitConfig))
	} else {
		builder.Add(RequestSizeLimitBytes(5 * 1024 * 1024)) // 5MB default
	}

	// 7. Rate Limiting
	if rateLimitConfig != nil {
		builder.Add(RateLimitWithConfig(rateLimitConfig))
	}

	// 8. Timeout
	if timeoutConfig != nil {
		builder.Add(Timeout(timeoutConfig))
	} else {
		builder.Add(TimeoutWithDuration(30 * time.Second))
	}

	return builder
}

// ControlServerChain builds the standard middleware chain for Control Server
func ControlServerChain(
	logger *logging.Logger,
	ipAllowlistConfig *IPAllowlistConfig,
	mtlsConfig *MTLSConfig,
	corsConfig *CORSConfig,
	rateLimitConfig *RateLimitConfig,
	sizeLimitConfig *SizeLimitConfig,
	timeoutConfig *TimeoutConfig,
) *ChainBuilder {
	builder := NewChainBuilder()

	// 1. Request ID (generate correlation ID)
	builder.Add(RequestID())

	// 2. Logging
	builder.Add(Logging(logger, &LoggingConfig{
		SkipPaths: map[string]bool{"/health": true}, // Skip health checks
	}))

	// 3. Recovery (catch panics from anything below)
	builder.Add(Recovery(logger))

	// 4. Security Headers
	builder.Add(SecurityHeaders(DefaultSecurityHeadersConfig()))

	// 5. IP Allowlist (for deployment mode enforcement)
	if ipAllowlistConfig != nil {
		builder.Add(IPAllowlist(ipAllowlistConfig))
	}

	// 6. mTLS Certificate Validation
	if mtlsConfig != nil {
		builder.Add(MTLSValidator(mtlsConfig))
	}

	// 7. CORS (for BFF or web UI access)
	if corsConfig != nil {
		builder.Add(CORS(corsConfig))
	}

	// 8. Request Size Limit (smaller for control operations)
	if sizeLimitConfig != nil {
		builder.Add(RequestSizeLimit(sizeLimitConfig))
	} else {
		builder.Add(RequestSizeLimitBytes(1 * 1024 * 1024)) // 1MB default
	}

	// 9. Rate Limiting (more permissive for admin)
	if rateLimitConfig != nil {
		builder.Add(RateLimitWithConfig(rateLimitConfig))
	}

	// 10. Timeout (some admin operations might take longer)
	if timeoutConfig != nil {
		builder.Add(Timeout(timeoutConfig))
	} else {
		builder.Add(TimeoutWithDuration(60 * time.Second))
	}

	return builder
}
