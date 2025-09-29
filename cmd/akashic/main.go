package main

import (
	"akashic/akashic/pkg/command"
	"os"
)

func main() {
	cmd := command.NewRootCmd()
	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
