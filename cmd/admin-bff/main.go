// admin-bff is the Akashic admin web UI's Backend-For-Frontend.
//
// It terminates browser requests on the docker network, forwards them
// to the control plane over mTLS using bff-client.{crt,key} (issued by
// Vault Agent, rotated in place), and serves the embedded React app.
//
// Phase 6 scope: bootstrap-only. /api/bootstrap/{status,create-root}
// and the static SPA assets. Login flow + admin dashboard are Phase 7.
package main

import (
	"embed"
	"fmt"
	"io/fs"
	"os"

	"akashic/akashic/pkg/admin_bff"
)

// FE assets are embedded from cmd/admin-bff/dist/, which is populated
// by `npm run build` (vite outputs there directly via vite.config.ts).
// The `all:` prefix preserves files starting with `_` or `.`.
//
//go:embed all:dist
var feAssetsRaw embed.FS

func main() {
	// Strip the leading "dist/" prefix so URLs map cleanly:
	// /index.html (URL) → dist/index.html (embed) becomes
	// /index.html (URL) → /index.html (sub-FS).
	feAssets, err := fs.Sub(feAssetsRaw, "dist")
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin-bff: embed unwrap failed: %v\n", err)
		os.Exit(1)
	}

	srv, err := admin_bff.NewServer(feAssets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin-bff: init failed: %v\n", err)
		os.Exit(1)
	}
	if err := srv.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "admin-bff: run failed: %v\n", err)
		os.Exit(1)
	}
}
