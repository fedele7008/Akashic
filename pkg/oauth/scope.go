package oauth

import (
	"errors"
	"sort"
	"strings"
)

// Scope handling helpers — used by client_services validation
// (required ∪ optional ⊆ tenant ceiling, required ∩ optional = ∅),
// the /authorize handler (request scope ⊆ allowed), and the
// consent screen template (split required vs optional).
//
// Scopes are space-separated strings throughout the codebase
// (matches OAuth on the wire). These helpers handle:
//   - parsing into a deduplicated, sorted set
//   - subset / disjoint / union / intersection set ops
//   - validating individual scope tokens against the OAuth charset
//
// Set operations return joined-and-sorted strings so the result is
// deterministic for storage (no spurious updated_at bumps from
// reordering on save).

// SpecialScopes are scopes that require per-client admin approval
// via the scope-request workflow (Phase B). Even when listed in the
// tenant ceiling `AllowedClientScopes`, these scopes can't be
// directly added to a client's required/optional sets — operators
// must approve a request first. `offline_access` is the
// initial inhabitant; future deployments may extend the list.
//
// The list is hardcoded today rather than table-driven because the
// surrounding workflow (request form fields, approval logic) is
// scope-specific. When a second special scope arrives, this is the
// natural place to extend.
var SpecialScopes = map[string]struct{}{
	RefreshScopeOfflineAccess: {},
}

// IsSpecialScope reports whether a scope token is one of the
// hardcoded special scopes.
func IsSpecialScope(scope string) bool {
	_, ok := SpecialScopes[scope]
	return ok
}

// ParseScopes splits a space-separated scope string into a
// deduplicated string slice in stable lexicographic order. Empty
// input → empty slice (callers handle the empty-set semantics).
//
// Trims whitespace and ignores empty tokens — `"  openid   email  "`
// parses to `["email", "openid"]`. Case-sensitive: OAuth scope
// matching is exact-string per RFC 6749 §3.3.
func ParseScopes(s string) []string {
	tokens := strings.Fields(s)
	if len(tokens) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tokens))
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ScopeSet is a parsed scope-set with O(1) membership check. Wraps
// the parsed slice for set algebra without re-tokenising on every
// operation. Returned by ParseScopeSet; callers do `set.Contains("openid")`
// or pass it to subset/disjoint helpers.
type ScopeSet struct {
	tokens []string // sorted, deduped
	idx    map[string]struct{}
}

// ParseScopeSet is the typed companion to ParseScopes.
func ParseScopeSet(s string) ScopeSet {
	tokens := ParseScopes(s)
	idx := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		idx[t] = struct{}{}
	}
	return ScopeSet{tokens: tokens, idx: idx}
}

// Contains reports whether the set contains the given scope.
func (s ScopeSet) Contains(scope string) bool {
	_, ok := s.idx[scope]
	return ok
}

// IsEmpty reports whether the set has no scopes.
func (s ScopeSet) IsEmpty() bool { return len(s.tokens) == 0 }

// String returns the canonical (sorted, space-joined) form. Used
// for storage so rows don't drift on save.
func (s ScopeSet) String() string {
	return strings.Join(s.tokens, " ")
}

// Tokens returns the sorted slice of scope tokens. Read-only.
func (s ScopeSet) Tokens() []string { return s.tokens }

// IsSubsetOf returns true iff every scope in s is also in other.
func (s ScopeSet) IsSubsetOf(other ScopeSet) bool {
	for _, t := range s.tokens {
		if _, ok := other.idx[t]; !ok {
			return false
		}
	}
	return true
}

// IsDisjointFrom returns true iff s and other share no scopes.
// Used to enforce required ∩ optional = ∅ on a client row.
func (s ScopeSet) IsDisjointFrom(other ScopeSet) bool {
	for _, t := range s.tokens {
		if _, ok := other.idx[t]; ok {
			return false
		}
	}
	return true
}

// UnionScopes returns the canonical (sorted, space-joined) union
// of two scope strings. Used by client create/update to maintain
// the `AllowedScopes = RequiredScopes ∪ OptionalScopes` invariant.
func UnionScopes(a, b string) string {
	merged := make(map[string]struct{})
	for _, t := range ParseScopes(a) {
		merged[t] = struct{}{}
	}
	for _, t := range ParseScopes(b) {
		merged[t] = struct{}{}
	}
	if len(merged) == 0 {
		return ""
	}
	out := make([]string, 0, len(merged))
	for t := range merged {
		out = append(out, t)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// ─── Validation ─────────────────────────────────────────────────

// validScopeTokenRegex would be the canonical match. We avoid the
// regexp import + compile cost and inline the predicate — same
// charset as RFC 6749 §3.3 (printable ASCII excluding double-quote
// and backslash, no spaces). Length cap of 128 is internal — the
// spec doesn't impose one but a 128-char scope name is unreasonable.
func isValidScopeToken(t string) bool {
	if t == "" || len(t) > 128 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 0x21 || c > 0x7E {
			return false
		}
		if c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// ValidateScopeString returns an error if the input contains
// invalid scope tokens. Empty string is allowed (callers decide
// whether the field should be empty).
func ValidateScopeString(s string) error {
	for _, t := range ParseScopes(s) {
		if !isValidScopeToken(t) {
			return errors.New("invalid scope token: " + t)
		}
	}
	return nil
}

// ValidateClientScopeSplit enforces the per-client invariant:
//
//   1. required ⊆ allowedCeiling
//   2. optional ⊆ allowedCeiling
//   3. required ∩ optional = ∅
//
// The ceiling itself is the operator's tenant policy
// `AllowedClientScopes`. Returns the first failure with a
// human-readable message; nil on success.
func ValidateClientScopeSplit(required, optional, allowedCeiling string) error {
	req := ParseScopeSet(required)
	opt := ParseScopeSet(optional)
	ceiling := ParseScopeSet(allowedCeiling)

	for _, t := range req.tokens {
		if !ceiling.Contains(t) {
			return errors.New("required scope not allowed by tenant policy: " + t)
		}
	}
	for _, t := range opt.tokens {
		if !ceiling.Contains(t) {
			return errors.New("optional scope not allowed by tenant policy: " + t)
		}
	}
	if !req.IsDisjointFrom(opt) {
		return errors.New("a scope cannot be both required and optional; pick one")
	}
	return nil
}

// EffectiveRequiredScopes is the read-time fallback for clients
// that pre-date the required/optional split. If RequiredScopes is
// empty AND AllowedScopes is non-empty, treat the entire
// AllowedScopes as required (the safe default — preserves the
// pre-split "everything is mandatory" behavior).
func EffectiveRequiredScopes(required, allowedLegacy string) string {
	if strings.TrimSpace(required) != "" {
		return required
	}
	return allowedLegacy
}
