package response

import (
	"encoding/json"
	"net/http"
)

// HTTP Headers
const (
	HeaderContentType = "Content-Type"
)

// Content Types
const (
	ContentTypeJSON = "application/json"
)

// Common HTTP status codes (for clarity and consistency)
const (
	StatusOK                  = http.StatusOK                  // 200
	StatusConflict            = http.StatusConflict            // 409
	StatusMethodNotAllowed    = http.StatusMethodNotAllowed    // 405
	StatusInternalServerError = http.StatusInternalServerError // 500
)

// Response represents a standardized API response
type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Error   *Error `json:"error,omitempty"`
}

// Error represents an API error with details
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Common error codes
const (
	ErrInternalServer       = "INTERNAL_SERVER_ERROR"
	ErrInvalidRequest       = "INVALID_REQUEST"
	ErrNotFound             = "NOT_FOUND"
	ErrAuthServerNotRunning = "AUTH_SERVER_NOT_RUNNING"
	ErrAuthServerRunning    = "AUTH_SERVER_ALREADY_RUNNING"
	ErrAuthServerStarting   = "AUTH_SERVER_STARTING"
	ErrAuthServerStopping   = "AUTH_SERVER_STOPPING"
	ErrAuthServerError      = "AUTH_SERVER_ERROR"
	ErrConfigReloadFailed   = "CONFIG_RELOAD_FAILED"
	ErrMethodNotAllowed     = "METHOD_NOT_ALLOWED"
	ErrEncodingError        = "ENCODING_ERROR"
	ErrTLSReloadFailed      = "TLS_RELOAD_FAILED"
)

// Success creates a successful response with data
func Success(data any) Response {
	return Response{
		Success: true,
		Data:    data,
	}
}

// Fail creates an error response
func Fail(code, message string, details map[string]any) Response {
	return Response{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
			Details: details,
		},
	}
}

// WriteJSON writes a JSON response to the ResponseWriter
func WriteJSON(w http.ResponseWriter, status int, response Response) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		msg := "Failed to encode response"
		fallbackResponse := Fail(ErrEncodingError, msg, nil)

		if fallbackBytes, marshalErr := json.Marshal(fallbackResponse); marshalErr == nil {
			w.Write(fallbackBytes)
		}
	}
}
