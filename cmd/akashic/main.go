package main

import (
	"akashic/akashic/pkg/akashic/cmd"

	"os"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
