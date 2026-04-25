package main

import (
	"akashic/akashic/pkg/cli/cmd"
)

func main() {
	// HandleExitError translates structured *exitError values from the
	// bootstrap subcommands into specific os.Exit(N) codes (2=token,
	// 3=validation, 4=rate, 5=config, 6=network, 7=server). Generic
	// errors fall back to exit 1.
	cmd.HandleExitError(cmd.NewRootCmd().Execute())
}
