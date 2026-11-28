// Command nas-unlock-api serves Authentik-gated browser unlock on a Unix
// socket and passes the KeePass password to nas-secrets on stdin.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
	"github.com/TheDirepack/Nix-nas/go/internal/unlockapi"
)

func envPath(name, fallback string) (syspath.Abs, error) {
	v := os.Getenv(name)
	if v == "" {
		v = fallback
	}
	return syspath.NewAbs(v)
}

func envProgram(name, fallback string) cmdexec.Program {
	if v := os.Getenv(name); v != "" {
		return cmdexec.Program(v)
	}
	return cmdexec.Program(fallback)
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	fs := flag.NewFlagSet("nas-unlock-api", flag.ContinueOnError)
	socketPath := fs.String("socket-path", "", "absolute Unix socket path")
	pol := registerPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if *socketPath == "" {
		fmt.Fprintln(os.Stderr, "nas-unlock-api: --socket-path is required")
		return 2
	}
	sock, err := syspath.NewAbsNoDotDot(*socketPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nas-unlock-api requires an absolute socket path")
		return 1
	}
	if err := pol.requireRoot(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ready, err1 := envPath("NAS_SECRET_READY", "/run/nas-secret-runtime/live/ready")
	state, err2 := envPath("NAS_SETUP_STATE", "/var/lib/nas-setup/state.json")
	if err := errors.Join(err1, err2); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logger := newLogger()
	host := &unlockapi.Host{
		SecretReady:  ready,
		SetupState:   state,
		NASSecrets:   envProgram("NAS_SECRETS_BIN", "nas-secrets"),
		Systemctl:    envProgram("NAS_SYSTEMCTL", "systemctl"),
		Runner:       cmdexec.NewOS(),
		Log:          logger,
		ActivationIn: pol.activationLimit(),
	}
	server := &unlockapi.Server{Host: host, Activator: host, Throttle: unlockapi.NewThrottle(nil)}

	if st, err := os.Lstat(sock.String()); err == nil && st.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(sock.String())
	}
	ln, err := net.Listen("unix", sock.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "nas-unlock-api: %v\n", err)
		return 1
	}
	if group := os.Getenv("NAS_CADDY_GROUP"); group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nas-unlock-api: %v\n", err)
			return 1
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(sock.String(), 0, gid); err != nil {
			fmt.Fprintf(os.Stderr, "nas-unlock-api: %v\n", err)
			return 1
		}
	}
	if err := os.Chmod(sock.String(), 0o660); err != nil { // #nosec -- group-shared socket is the contract
		fmt.Fprintf(os.Stderr, "nas-unlock-api: %v\n", err)
		return 1
	}
	httpServer := unlockapi.NewHTTPServer(server)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		_ = httpServer.Close()
	}()
	logger.Notice("nas-unlock-api listening on unix:" + sock.String())
	err = httpServer.Serve(unlockapi.NewPeerListener(ln, pol.allowedUIDs()))
	_ = os.Remove(sock.String())
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "nas-unlock-api: %v\n", err)
		return 1
	}
	return 0
}
