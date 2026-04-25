package core

import (
	"fmt"
	"os"
	"strings"

	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/server/auth"
	"akashic/akashic/pkg/server/control"
)

// accessURL turns a server's bind address into a URL an operator can paste
// into curl or a browser. Two transformations:
//
//  1. Pick the right scheme: "https://" if TLS is enabled, "http://" otherwise.
//  2. Replace wildcard bind hosts (0.0.0.0, ::) with their loopback equivalents
//     (127.0.0.1, [::1]). 0.0.0.0 is a *bind* address meaning "listen on all
//     interfaces"; you cannot actually connect() to it. Showing it in a banner
//     teaches operators the wrong URL. Loopback is the safe default that works
//     from the host machine in every deployment mode.
//
// bindAddr is expected as "host:port" form (what http.Server.Addr looks like).
func accessURL(bindAddr string, tlsEnabled bool) string {
	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	// IPv4 wildcard → IPv4 loopback
	bindAddr = strings.Replace(bindAddr, "0.0.0.0:", "127.0.0.1:", 1)
	// IPv6 wildcard → IPv6 loopback (e.g. "[::]:8080" → "[::1]:8080")
	bindAddr = strings.Replace(bindAddr, "[::]:", "[::1]:", 1)
	return fmt.Sprintf("%s://%s", scheme, bindAddr)
}

// collectReloaders gathers every *pki.Reloader currently installed on the
// started servers. Nil reloaders (TLS disabled) are skipped.
func collectReloaders(ctrl *control.Server, authSrv *auth.Server) []*pki.Reloader {
	out := make([]*pki.Reloader, 0, 2)
	if ctrl != nil {
		if r := ctrl.CertReloader(); r != nil {
			out = append(out, r)
		}
	}
	if authSrv != nil {
		if r := authSrv.CertReloader(); r != nil {
			out = append(out, r)
		}
	}
	return out
}

// VerbosePrintlnf implements the app.VerbosePrinter interface
func (app *AkashicApp) VerbosePrintlnf(format string, args ...any) {
	if app.GetVerbose() {
		if app.Logger == nil {
			// If logger is not set yet, print to stderr
			fmt.Fprintf(os.Stderr, "[VERBOSE] "+format+"\n", args...)
		} else {
			app.Logger.App.Debug(fmt.Sprintf(format, args...))
		}
	}
}

func (app *AkashicApp) GetVerbose() bool {
	return app.verbose
}

func (app *AkashicApp) SetVerbose(v bool) {
	app.verbose = v
}
