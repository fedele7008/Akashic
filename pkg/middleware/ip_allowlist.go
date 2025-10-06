package middleware

import (
	"net"
	"net/http"
	"strings"
)

// IPAllowlistConfig holds configuration for IP allowlisting
type IPAllowlistConfig struct {
	// AllowedIPs is a list of allowed IP addresses or CIDR ranges
	AllowedIPs []string

	// AllowLoopback determines if loopback addresses are always allowed
	AllowLoopback bool

	// TrustProxy determines if X-Forwarded-For header should be used
	TrustProxy bool
}

// DefaultIPAllowlistConfig returns sensible defaults
func DefaultIPAllowlistConfig() *IPAllowlistConfig {
	return &IPAllowlistConfig{
		AllowedIPs:    []string{},
		AllowLoopback: true,
		TrustProxy:    false,
	}
}

// IPAllowlist creates a middleware that restricts access to allowed IPs
func IPAllowlist(config *IPAllowlistConfig) Middleware {
	if config == nil {
		config = DefaultIPAllowlistConfig()
	}

	// Pre-parse CIDR ranges for performance
	allowedNets := make([]*net.IPNet, 0)
	allowedIPs := make([]net.IP, 0)

	for _, ipStr := range config.AllowedIPs {
		// Check if it's a CIDR range
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err == nil {
				allowedNets = append(allowedNets, ipNet)
			}
		} else {
			// Single IP
			ip := net.ParseIP(ipStr)
			if ip != nil {
				allowedIPs = append(allowedIPs, ip)
			}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract IP from request
			var clientIP string

			if config.TrustProxy {
				// Use X-Forwarded-For if behind proxy
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					// Take the first IP in the chain
					ips := strings.Split(xff, ",")
					clientIP = strings.TrimSpace(ips[0])
				}
			}

			// Fall back to RemoteAddr if no X-Forwarded-For
			if clientIP == "" {
				// Remove port if present
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					clientIP = r.RemoteAddr
				} else {
					clientIP = host
				}
			}

			// Parse client IP
			ip := net.ParseIP(clientIP)
			if ip == nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Check if loopback and allowed
			if config.AllowLoopback && ip.IsLoopback() {
				next.ServeHTTP(w, r)
				return
			}

			// Check against allowed IPs
			for _, allowedIP := range allowedIPs {
				if ip.Equal(allowedIP) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// Check against allowed networks
			for _, allowedNet := range allowedNets {
				if allowedNet.Contains(ip) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// IP not allowed
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}
