package main

import (
	"akashic/akashic/pkg/cli/cmd"

	"os"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
