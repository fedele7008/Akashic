package middleware

import (
	"akashic/akashic/pkg/logging"
	"fmt"
	"net/http"
	"runtime/debug"

	"go.uber.org/zap"
)

// Recovery creates a middleware that recovers from panics
// This should be near the outermost layer (after logging) to catch all panics
func Recovery(logger *logging.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Capture stack trace
					stack := debug.Stack()

					// Log the panic to security channel (potential security issue)
					fields := []zap.Field{
						zap.String("method", r.Method),
						zap.String("path", r.URL.Path),
						zap.String("remote_addr", r.RemoteAddr),
						zap.Any("panic", err),
						zap.String("stack", string(stack)),
						zap.String("request_id", GetRequestID(r)),
					}

					logger.Security.Error(fmt.Sprintf("PANIC RECOVERY: request-id: %s\n", GetRequestID(r)), fields...)

					// Return 500 Internal Server Error
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}
