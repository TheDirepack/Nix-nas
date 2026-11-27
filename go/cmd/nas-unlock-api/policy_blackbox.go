//go:build nasblackbox

// The nasblackbox build exists only for the Python black-box tests: it may
// run unprivileged, admits an explicit peer uid and logs to stderr. The
// production build has none of these flags.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type policy struct {
	uid     *uint
	timeout *time.Duration
}

func registerPolicyFlags(fs *flag.FlagSet) policy {
	return policy{
		uid:     fs.Uint("test-allow-peer-uid", 0, "black-box tests: admitted peer uid"),
		timeout: fs.Duration("test-activation-timeout", 0, "black-box tests: activation limit"),
	}
}

func (policy) requireRoot() error { return nil }

func (p policy) allowedUIDs() map[uint32]bool { return map[uint32]bool{uint32(*p.uid): true} } // #nosec -- test uid

func (p policy) activationLimit() time.Duration { return *p.timeout }

type journal struct{}

func (journal) Notice(msg string) { fmt.Fprintln(os.Stderr, msg) }

func newLogger() journal { return journal{} }
