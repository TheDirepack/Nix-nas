// Package hardening restricts process memory disclosure before secret input.
package hardening

import (
	"errors"

	"golang.org/x/sys/unix"
)

func DisableDumps() error {
	return errors.Join(
		unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}),
		unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0),
	)
}
