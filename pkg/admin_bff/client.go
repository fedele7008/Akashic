package admin_bff

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"akashic/akashic/pkg/pki"
)

// ControlClient is the BFF's typed client for the Akashic control plane.
// All outbound requests use mTLS authenticated by the bff-client cert
// (CN bff.akashic.local), which is rotated in place by Vault Agent.
//
// The client uses tls.Config.GetClientCertificate as a callback that's
// invoked per-handshake -- this is the client-side analogue of Phase
// 4's server-side GetCertificate pattern. The Reloader holds the
// current cert in an atomic pointer; when Vault Agent writes a new
// cert+key pair to disk, the optional fsnotify watcher (Step 4) calls
// Reloader.Reload(), which atomically swaps the pointer. Subsequent
// handshakes pick up the new cert; in-flight connections finish on
// the old one and naturally close.
type ControlClient struct {
	base    string
	httpC   *http.Client
	reloadr *pki.Reloader
}

// NewControlClient constructs the client. Returns an error if the
// initial cert load fails (we won't be able to authenticate; nothing
// useful to do later).
func NewControlClient(cfg *Config) (*ControlClient, error) {
	reloadr, err := pki.NewReloader("admin-bff-client", cfg.BFFCertFile, cfg.BFFKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load BFF client cert: %w", err)
	}

	caPool, err := pki.LoadCAPool(cfg.BFFCAFile)
	if err != nil {
		return nil, fmt.Errorf("load BFF CA bundle: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
			// GetClientCertificate is consulted per TLS handshake, so
			// rotation works with no listener restart. The CertificateRequestInfo
			// argument is ignored -- the control plane only accepts certs
			// signed by pki-mtls-akashic-ctrl, and we have exactly one
			// cert available, so there's nothing to select between.
			GetClientCertificate: func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return reloadr.GetCertificate(nil)
			},
		},
		// Don't keep connections idle forever; helps cert rotation
		// take effect promptly even without explicit watcher signals.
		IdleConnTimeout: 90 * time.Second,
	}

	return &ControlClient{
		base: cfg.ControlURL,
		httpC: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		},
		reloadr: reloadr,
	}, nil
}

// Reloader returns the cert reloader so the optional cert watcher
// (Step 4) can subscribe to it. Mirrors the same pattern the Akashic
// server uses to expose its reloader to the watcher in Phase 4.
func (c *ControlClient) Reloader() *pki.Reloader {
	return c.reloadr
}

// BootstrapStatus is the shape of GET /bootstrap/status's response.data.
// Mirrors the server-side bootstrap_handlers.go output exactly.
type BootstrapStatus struct {
	IsComplete      bool   `json:"is_complete"`
	CompletedAt     string `json:"completed_at,omitempty"`
	RootUserID      string `json:"root_user_id,omitempty"`
	TokenExists     bool   `json:"token_exists,omitempty"`
	TokenTTLSeconds int    `json:"token_ttl_seconds,omitempty"`
}

// CreateRootRequest is the body the BFF forwards to /bootstrap/root.
// Field names match the server's expected JSON.
type CreateRootRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CreateRootResponse is the shape the server returns on success.
// We pass most of this back to the browser unchanged.
type CreateRootResponse struct {
	User map[string]any `json:"user"`
}

// envelope mirrors pkg/server/response's standard envelope.
type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// ControlError is the error type returned when the control plane
// responds with a structured failure. The BFF's handlers use the Code
// field to map to user-friendly messages and HTTP statuses.
type ControlError struct {
	HTTPStatus int
	Code       string
	Message    string
	Details    map[string]any
}

func (e *ControlError) Error() string {
	return fmt.Sprintf("control plane: %s (%d): %s", e.Code, e.HTTPStatus, e.Message)
}

// BootstrapStatusGet calls GET /bootstrap/status. This endpoint is
// reachable in both bootstrap and normal modes -- it's the server's
// own answer to "are you in bootstrap mode?", so the BFF treats it
// as always-callable.
func (c *ControlClient) BootstrapStatusGet(ctx context.Context) (*BootstrapStatus, error) {
	resp, body, err := c.do(ctx, http.MethodGet, "/bootstrap/status", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out BootstrapStatus
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed status payload: %w", err)
	}
	return &out, nil
}

// BootstrapCreateRoot calls POST /bootstrap/root with the form data.
// Returns ControlError for 4xx/5xx responses so handlers can map
// specific error codes to user messages.
func (c *ControlClient) BootstrapCreateRoot(ctx context.Context, req *CreateRootRequest) (*CreateRootResponse, error) {
	resp, body, err := c.do(ctx, http.MethodPost, "/bootstrap/root", req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out CreateRootResponse
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed create-root payload: %w", err)
	}
	return &out, nil
}

// CreateClientRequest mirrors the control plane's
// adminCreateClientRequest shape (pkg/server/control/clients_handlers.go).
// Field names match the JSON the control plane expects so this struct
// can be forwarded as-is.
//
// Keep this in sync with the control-plane struct: Go's default
// json.Decoder silently drops unknown fields, so a missing field
// here means the FE's value is dropped on the way through with no
// error — the very bug that hid IsTenantPortal not propagating
// when the admin-UI checkbox was ticked.
type CreateClientRequest struct {
	Name         string `json:"name"`
	ClientType   string `json:"client_type"` // "WEB" or "SPA"
	RedirectURIs string `json:"redirect_uris"`
	Description  string `json:"description,omitempty"`
	HomepageURL  string `json:"homepage_url,omitempty"`
	// RequirePKCE: WEB clients only — operator-configurable, default
	// true. Pointer (*bool) so we can distinguish "operator omitted"
	// (→ default true) from "operator explicitly set false". Forced
	// true for SPA regardless.
	RequirePKCE *bool `json:"require_pkce,omitempty"`
	// IsTenantPortal marks this client as first-party (operator-
	// owned). Any number of rows may carry the flag — operators
	// flag each first-party app they register. Operator-only (the
	// admin-bff is mTLS-trusted to the control plane on a CN
	// that's allowed to set this); the api-server's bearer-
	// authenticated /clients endpoint ignores this field on input,
	// so developers using the <akashic-clients> widget can't
	// self-promote.
	IsTenantPortal bool `json:"is_tenant_portal,omitempty"`
}

// ClientView mirrors the control-plane response shape for a single
// registered client.
type ClientView struct {
	ClientID       string `json:"client_id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	HomepageURL    string `json:"homepage_url,omitempty"`
	ClientType     string `json:"client_type"`
	Public         bool   `json:"public"`
	RedirectURIs   string `json:"redirect_uris"`
	AllowedScopes  string `json:"allowed_scopes"`
	AuthTypes      string `json:"auth_types"`
	BuiltIn        bool   `json:"built_in"`
	RequirePKCE    bool   `json:"require_pkce"`
	IsTenantPortal bool   `json:"is_tenant_portal"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
}

// CreateClientResponse is what the control plane returns on a
// successful POST /clients. The `client_secret` field is the
// plaintext, returned exactly ONCE for WEB clients and empty for SPA.
// The BFF passes this through to the FE unchanged so the operator
// can copy it from the dashboard's one-time-display panel.
type CreateClientResponse struct {
	Client       ClientView `json:"client"`
	ClientSecret string     `json:"client_secret,omitempty"`
}

// ClientCreate calls POST /clients with the form data. Returns
// ControlError for 4xx/5xx responses so handlers can map specific
// error codes to user messages (most notably VALIDATION_FAILED for
// missing client_type).
func (c *ControlClient) ClientCreate(ctx context.Context, req *CreateClientRequest) (*CreateClientResponse, error) {
	resp, body, err := c.do(ctx, http.MethodPost, "/clients", req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out CreateClientResponse
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed create-client payload: %w", err)
	}
	return &out, nil
}

// ListClientsResponse is the shape of GET /clients's data envelope.
type ListClientsResponse struct {
	Clients []ClientView `json:"clients"`
}

// ClientList calls GET /clients on the control plane and returns the
// full set of registered clients (built-in + tenant). Operator-level
// view: no per-owner scoping (the admin-bff is allowed to see all).
func (c *ControlClient) ClientList(ctx context.Context) (*ListClientsResponse, error) {
	resp, body, err := c.do(ctx, http.MethodGet, "/clients", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out ListClientsResponse
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed list-clients payload: %w", err)
	}
	return &out, nil
}

// ClientDelete calls DELETE /clients/<id> on the control plane.
// Built-ins and not-found are returned as ControlError with the
// appropriate code so the handler can map them to user-friendly
// browser messages.
func (c *ControlClient) ClientDelete(ctx context.Context, clientID string) error {
	resp, body, err := c.do(ctx, http.MethodDelete, "/clients/"+clientID, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return parseControlError(resp.StatusCode, body)
	}
	return nil
}

// RotateSecretResponse is the shape of POST /clients/:id/rotate-secret's
// data envelope. The plaintext is shown ONCE to the operator; only its
// bcrypt hash is persisted server-side.
type RotateSecretResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// SetupStatus is the shape of GET /admin/setup-status's response.data.
// Mirrors pkg/server/control/setup_status_handlers.go's output. Each
// field is a single boolean — the FE banner renders one row per false.
type SetupStatus struct {
	BootstrapComplete      bool `json:"bootstrap_complete"`
	TenantPortalRegistered bool `json:"tenant_portal_registered"`
	LDAPOK                 bool `json:"ldap_ok"`
}

// SetupStatusGet calls GET /admin/setup-status. Reachable in both
// bootstrap and post-bootstrap modes (the endpoint itself reports
// bootstrap state, so gating it on bootstrap completion would hide
// it exactly when it's most useful).
func (c *ControlClient) SetupStatusGet(ctx context.Context) (*SetupStatus, error) {
	resp, body, err := c.do(ctx, http.MethodGet, "/admin/setup-status", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out SetupStatus
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed setup-status payload: %w", err)
	}
	return &out, nil
}

// ClientRotateSecret calls POST /clients/<id>/rotate-secret. Rejected
// for built-ins and public/SPA clients server-side; the handler maps
// those codes to user-facing messages.
func (c *ControlClient) ClientRotateSecret(ctx context.Context, clientID string) (*RotateSecretResponse, error) {
	resp, body, err := c.do(ctx, http.MethodPost, "/clients/"+clientID+"/rotate-secret", nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, parseControlError(resp.StatusCode, body)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("malformed control plane response: %w", err)
	}
	var out RotateSecretResponse
	if err := json.Unmarshal(env.Data, &out); err != nil {
		return nil, fmt.Errorf("malformed rotate-secret payload: %w", err)
	}
	return &out, nil
}

// do is the shared HTTP-call helper. Returns the response, body bytes,
// and a low-level error (network/timeout). Higher-level callers
// inspect the status code and parse the body as needed.
//
// Body is fully buffered before return so the caller can both inspect
// the status code and parse the JSON without juggling stream lifecycles.
func (c *ControlClient) do(ctx context.Context, method, path string, body any) (*http.Response, []byte, error) {
	var bodyReader *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(data)
	}

	url := c.base + path
	var req *http.Request
	var err error
	if bodyReader != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bodyReader)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpC.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, respBody, nil
}

// parseControlError extracts the {error: {code, message, details}}
// envelope into a ControlError. If the body isn't a valid envelope,
// returns a generic ControlError with the raw body in the message.
func parseControlError(status int, body []byte) error {
	var env envelope
	if err := json.Unmarshal(body, &env); err == nil && env.Error != nil {
		return &ControlError{
			HTTPStatus: status,
			Code:       env.Error.Code,
			Message:    env.Error.Message,
			Details:    env.Error.Details,
		}
	}
	return &ControlError{
		HTTPStatus: status,
		Code:       "UNKNOWN",
		Message:    string(body),
	}
}
