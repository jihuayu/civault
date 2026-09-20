package main

import (
	"civault/internal/cli"
	"os"
)

func main() {
	if cli.New(os.Stdin, os.Stdout, os.Stderr).Execute() != nil {
		os.Exit(1)
	}
}
