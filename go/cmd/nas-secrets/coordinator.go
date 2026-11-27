package main

import (
	"os"
	osexec "os/exec"

	"github.com/TheDirepack/Nix-nas/go/internal/txn"
)

// exec runs the coordinator validation with inherited stdio except stdin,
// which carries the KeePass password and must reach only this process.
func exec(path string, args ...string) txn.Exit {
	c := osexec.Command(path, args...) // #nosec -- pinned coordinator path
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if e, ok := err.(*osexec.ExitError); ok && e.ExitCode() > 0 && e.ExitCode() < 256 {
			return txn.Exit(e.ExitCode()) // #nosec G115 -- range checked above
		}
		return 1
	}
	return 0
}
