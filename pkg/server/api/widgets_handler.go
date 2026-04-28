package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"akashic/akashic/pkg/server/response"
)

// Widget bundle hosting (Phase 8b).
//
// The api-server serves the embeddable Web Component bundle at:
//
//   GET /widgets/akashic.js          ← compiled Lit-based widget bundle
//   GET /widgets/akashic.js.map      ← sourcemap (if present)
//   GET /widgets/akashic-default.css ← optional default stylesheet
//
// Why on api.<tenant> rather than auth.<tenant>: keeps the auth
// server pure-OIDC; co-locates the widget bundle with the API it
// calls, so tenants point at one origin for "data + reference
// client." See doc/phase-8b-pivot-plan.md for the full rationale.
//
// The bundle is baked into the akashic image at /usr/local/share/akashic-widgets/
// by the widget-builder stage of services/akashic/Dockerfile. In dev,
// AKASHIC_WIDGETS_DIR overrides the location so contributors can point
// at their local web/widgets/dist/ for fast iteration.
//
// CORS: <script> tags don't trigger CORS preflight, and stylesheets
// loaded via <link> only need CORS if the browser wants to apply
// crossorigin attribute checks. We keep the response permissive
// (Access-Control-Allow-Origin: *) for static assets — they're
// public artefacts with no per-tenant secrets in them.

const (
	widgetsDirEnv     = "AKASHIC_WIDGETS_DIR"
	widgetsDefaultDir = "/usr/local/share/akashic-widgets"
)

var (
	widgetsResolveOnce sync.Once
	resolvedWidgetsDir string
)

// widgetsDir returns the absolute filesystem directory the bundle
// is served from. Reads AKASHIC_WIDGETS_DIR if set, falls back to
// the baked-in image path. Memoised — env doesn't change at runtime.
func widgetsDir() string {
	widgetsResolveOnce.Do(func() {
		if v := os.Getenv(widgetsDirEnv); v != "" {
			resolvedWidgetsDir = v
			return
		}
		resolvedWidgetsDir = widgetsDefaultDir
	})
	return resolvedWidgetsDir
}

// allowedWidgetFiles enumerates the files the handler will serve.
// Anything not on this list returns 404 — prevents path-traversal
// attempts via /widgets/../something even though Go's http.ServeFile
// already protects against that, defense in depth costs nothing here.
var allowedWidgetFiles = map[string]string{
	"akashic.js":          "application/javascript; charset=utf-8",
	"akashic.js.map":      "application/json; charset=utf-8",
	"akashic-default.css": "text/css; charset=utf-8",
}

// handleWidgetAsset serves a single file from the widget bundle
// directory. Mounted at /widgets/* on the api server's mux.
func (s *Server) handleWidgetAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		response.WriteJSON(w, http.StatusMethodNotAllowed,
			response.Fail(response.ErrMethodNotAllowed, "only GET/HEAD on /widgets/*", nil))
		return
	}

	// Strip the route prefix and pull the basename.
	name := strings.TrimPrefix(r.URL.Path, "/widgets/")
	if name == "" || strings.ContainsAny(name, `/\`) {
		http.NotFound(w, r)
		return
	}
	contentType, ok := allowedWidgetFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	full := filepath.Join(widgetsDir(), name)
	f, err := os.Open(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()

	// Static asset headers — cacheable, public, CORS-permissive.
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// X-Content-Type-Options nosniff prevents browsers from sniffing
	// JS as something else; small hardening.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	stat, err := f.Stat()
	if err != nil {
		// File opened but stat failed — exotic. Treat as server error.
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.ServeContent(w, r, name, stat.ModTime(), f)
}
