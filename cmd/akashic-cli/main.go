package main

import (
	"akashic/akashic/pkg/command/cli"
	"os"
)

func main() {
	cmd := cli.NewRootCmd()
	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
