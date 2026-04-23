package core

import (
	"fmt"
	"os"

	"akashic/akashic/pkg/pki"
	"akashic/akashic/pkg/server/auth"
	"akashic/akashic/pkg/server/control"
)

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
