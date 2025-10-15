package core

import (
	"fmt"
	"os"
)

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
