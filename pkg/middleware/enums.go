package middleware

import "fmt"

// XFrameOptions defines the X-Frame-Options header policy
type XFrameOptions string

const (
	// XFrameOptionsDeny prevents any domain from framing the content
	XFrameOptionsDeny XFrameOptions = "DENY"
	// XFrameOptionsSameOrigin allows framing only from the same origin
	XFrameOptionsSameOrigin XFrameOptions = "SAMEORIGIN"
)

// String returns the string representation
func (x XFrameOptions) String() string {
	return string(x)
}

// Validate checks if the XFrameOptions value is valid
func (x XFrameOptions) Validate() error {
	switch x {
	case XFrameOptionsDeny, XFrameOptionsSameOrigin:
		return nil
	default:
		return fmt.Errorf("invalid X-Frame-Options value: %s (must be DENY or SAMEORIGIN)", x)
	}
}

// XSSProtectionPolicy defines the X-XSS-Protection header policy
type XSSProtectionPolicy string

const (
	// XSSProtectionDisabled disables XSS filtering (0)
	XSSProtectionDisabled XSSProtectionPolicy = "0"
	// XSSProtectionEnabled enables XSS filtering (1)
	XSSProtectionEnabled XSSProtectionPolicy = "1"
	// XSSProtectionBlock enables XSS filtering and blocks the page if attack detected
	XSSProtectionBlock XSSProtectionPolicy = "1; mode=block"
)

// String returns the string representation
func (x XSSProtectionPolicy) String() string {
	return string(x)
}

// Validate checks if the XSSProtectionPolicy value is valid
func (x XSSProtectionPolicy) Validate() error {
	switch x {
	case XSSProtectionDisabled, XSSProtectionEnabled, XSSProtectionBlock:
		return nil
	default:
		return fmt.Errorf("invalid X-XSS-Protection value: %s", x)
	}
}

// SameSitePolicy defines the SameSite cookie attribute
type SameSitePolicy string

const (
	// SameSiteStrict prevents the cookie from being sent in all cross-site browsing context
	SameSiteStrict SameSitePolicy = "Strict"
	// SameSiteLax allows the cookie to be sent with top-level navigations
	SameSiteLax SameSitePolicy = "Lax"
	// SameSiteNone allows the cookie to be sent in all contexts (requires Secure flag)
	SameSiteNone SameSitePolicy = "None"
)

// String returns the string representation
func (s SameSitePolicy) String() string {
	return string(s)
}

// Validate checks if the SameSitePolicy value is valid
func (s SameSitePolicy) Validate() error {
	switch s {
	case SameSiteStrict, SameSiteLax, SameSiteNone:
		return nil
	default:
		return fmt.Errorf("invalid SameSite value: %s (must be Strict, Lax, or None)", s)
	}
}

// RateLimitStrategy defines how rate limiting keys are extracted
type RateLimitStrategy string

const (
	// RateLimitByIP limits based on client IP address
	RateLimitByIP RateLimitStrategy = "ip"
	// RateLimitByClientID limits based on OAuth client_id
	RateLimitByClientID RateLimitStrategy = "client_id"
	// RateLimitByUser limits based on authenticated user
	RateLimitByUser RateLimitStrategy = "user"
	// RateLimitByIPAndClientID combines IP and client_id
	RateLimitByIPAndClientID RateLimitStrategy = "ip_and_client_id"
)

// String returns the string representation
func (r RateLimitStrategy) String() string {
	return string(r)
}

// Validate checks if the RateLimitStrategy value is valid
func (r RateLimitStrategy) Validate() error {
	switch r {
	case RateLimitByIP, RateLimitByClientID, RateLimitByUser, RateLimitByIPAndClientID:
		return nil
	default:
		return fmt.Errorf("invalid rate limit strategy: %s", r)
	}
}
