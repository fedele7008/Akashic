package main

import (
	"akashic/akashic/pkg/command/akashic"
	"os"
)

func main() {
	cmd := akashic.NewRootCmd()
	err := cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
