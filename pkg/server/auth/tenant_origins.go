package auth

import "strings"

// splitTenantOrigins parses the operator-supplied tenant-origins
// string (comma- or whitespace-separated) into a deduplicated slice.
// Empty input yields an empty slice — which the CORS middleware
// reads as "no origins allowed."
//
// Example inputs:
//
//	"https://acme.com,https://www.acme.com"
//	"https://acme.com, https://www.acme.com"
//	""
//
// Mirrored on the api-server side (pkg/server/api/tenant_origins.go)
// rather than shared, to avoid creating a tiny shared util package
// for two functions of the same body.
func splitTenantOrigins(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
