package akashiccli

import "time"

// Bootstrap types

// CreateRootRequest represents a request to create the root user
type CreateRootRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// BootstrapStatusResponse represents bootstrap status
type BootstrapStatusResponse struct {
	NeedsBootstrap  bool       `json:"needs_bootstrap"`
	IsComplete      bool       `json:"is_complete"`
	CreatedAt       time.Time  `json:"created_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	RootUserID      *string    `json:"root_user_id,omitempty"`
	TokenExists     bool       `json:"token_exists,omitempty"`
	TokenTTLSeconds int        `json:"token_ttl_seconds,omitempty"`
}

// User management types

// CreateUserRequest represents a request to create a user
type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UserType string `json:"user_type"` // "root", "admin", "user"
}

// UserResponse represents a user
type UserResponse struct {
	ID         string     `json:"uid"`
	Username   string     `json:"username"`
	Email      string     `json:"email"`
	UserType   string     `json:"user_type"`
	IsDisabled bool       `json:"is_disabled"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
	DisabledBy *string    `json:"disabled_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

type RootUserCreateUserResponse struct {
	ID        string    `json:"uid"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	UserType  string    `json:"user_type"`
	CreatedAt time.Time `json:"created_at"`
}

type RootUserCreateResponse struct {
	User    RootUserCreateUserResponse `json:"user"`
	Message string                     `json:"message"`
}

// Server control types

// ServerStatusResponse represents server status
type ServerStatusResponse struct {
	ControlServer ControlServerStatus `json:"control_server"`
	AuthServer    AuthServerStatus    `json:"auth_server"`
	Uptime        string              `json:"uptime"`
	PID           int                 `json:"pid"`
}

// ControlServerStatus represents control server status
type ControlServerStatus struct {
	Address string `json:"address"`
	State   string `json:"state"`
}

// AuthServerStatus represents auth server status
type AuthServerStatus struct {
	Uptime    string    `json:"uptime"`
	Address   string    `json:"address"`
	State     string    `json:"state"`
	StartedAt time.Time `json:"started_at"`
}

// Config types

// ConfigResponse represents the current configuration
type ConfigResponse map[string]any
