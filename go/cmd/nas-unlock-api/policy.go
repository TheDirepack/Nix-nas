//go:build !nasblackbox

package main

import (
	"errors"
	"flag"
	"log/syslog"
	"os"
	"os/user"
	"strconv"
	"time"
)

type policy struct{}

// caddyUIDs admits root and the Caddy service user.
func caddyUIDs() map[uint32]bool {
	allowed := map[uint32]bool{0: true}
	name := os.Getenv("NAS_CADDY_USER")
	if name == "" {
		name = "caddy"
	}
	if u, err := user.Lookup(name); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			allowed[uint32(uid)] = true
		}
	}
	return allowed
}

func registerPolicyFlags(*flag.FlagSet) policy { return policy{} }

func (policy) requireRoot() error {
	if os.Geteuid() != 0 {
		return errors.New("nas-unlock-api must run as root")
	}
	return nil
}

func (policy) allowedUIDs() map[uint32]bool { return caddyUIDs() }

func (policy) activationLimit() time.Duration { return 0 }

type journal struct{ w *syslog.Writer }

func (j journal) Notice(msg string) {
	if j.w != nil {
		_ = j.w.Notice(msg)
	}
}

func newLogger() journal {
	w, _ := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, "nas-unlock-api")
	return journal{w: w}
}
