package main

import (
	"os"

	"github.com/cynative/cynative/internal/cli"
)

// main is the primary entrypoint for the cynative cli.
func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(cli.ExitCodeFor(err))
	}
}
