package middleware

import (
	"akashic/akashic/pkg/logging"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// LoggingConfig holds configuration for the logging middleware
type LoggingConfig struct {
	// SkipPaths are paths to skip logging (e.g., /health for high-frequency checks)
	SkipPaths map[string]bool
}

// Logging creates a middleware that logs all HTTP requests
// This should be the OUTERMOST middleware to capture everything
func Logging(logger *logging.Logger, config *LoggingConfig) Middleware {
	if config == nil {
		config = &LoggingConfig{
			SkipPaths: make(map[string]bool),
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip logging for configured paths
			if config.SkipPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			// Record start time
			start := time.Now()

			// Wrap response writer to capture status code
			rw := NewResponseWriter(w)

			reqId := GetRequestID(r)

			inField := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
				zap.String("proto", r.Proto),
				zap.Dict("request_headers", headerFields(r.Header)...),
				zap.String("body", func() string {
					body, _ := io.ReadAll(r.Body)
					return string(body)
				}()),
				zap.Int64("request_size", r.ContentLength),
				zap.String("host", r.Host),
				zap.String("request_uri", r.RequestURI), // shows path along with query parameters
				zap.String("request_id", reqId),
			}
			// Log incoming request
			logger.App.Info(fmt.Sprintf("REQUEST RECEIVED: %s [%s] %s<-%s (%d bytes) \"%s\" request-id: %s\n",
				r.Proto,
				r.Method,
				r.Host,
				r.RemoteAddr,
				r.ContentLength,
				r.URL.Path,
				reqId), inField...)

			// Call next handler
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Log completion with status and duration
			outField := []zap.Field{
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
				zap.String("proto", r.Proto),
				zap.Dict("response_headers", headerFields(rw.Header())...),
				zap.Int("status", rw.StatusCode()),
				zap.Int("response_size", rw.BytesWritten()),
				zap.Duration("duration", duration),
				zap.String("host", r.Host),
				zap.String("request_uri", r.RequestURI), // shows path along with query parameters
				zap.String("request_id", reqId),
			}

			// Log to appropriate channel based on status code
			if rw.StatusCode() >= 500 {
				logger.App.Error(fmt.Sprintf("RESPONSE SENT (SERVER ERROR): %s [%s:%v] %s->%s (%d bytes) \"%s\" request-id: %s\n",
					r.Proto,
					r.Method,
					rw.StatusCode(),
					r.Host,
					r.RemoteAddr,
					rw.BytesWritten(),
					r.URL.Path,
					reqId), outField...)
			} else if rw.StatusCode() >= 400 {
				logger.App.Warn(fmt.Sprintf("RESPONSE SENT (CLIENT ERROR): %s [%s:%v] %s->%s (%d bytes) \"%s\" request-id: %s\n",
					r.Proto,
					r.Method,
					rw.StatusCode(),
					r.Host,
					r.RemoteAddr,
					rw.BytesWritten(),
					r.URL.Path,
					reqId), outField...)
			} else {
				logger.App.Info(fmt.Sprintf("RESPONSE SENT: %s [%s:%v] %s->%s (%d bytes) \"%s\" request-id: %s\n",
					r.Proto,
					r.Method,
					rw.StatusCode(),
					r.Host,
					r.RemoteAddr,
					rw.BytesWritten(),
					r.URL.Path,
					reqId), outField...)
			}
		})
	}
}

func headerFields(h http.Header) []zap.Field {
	f := make([]zap.Field, 0, len(h))
	for k, vs := range h {
		if len(vs) == 1 {
			f = append(f, zap.String(k, vs[0]))
		} else {
			f = append(f, zap.Strings(k, vs))
		}
	}
	return f
}
