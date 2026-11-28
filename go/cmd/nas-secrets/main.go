// Command nas-secrets activates KeePassXC-backed runtime secrets.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/config"
	"github.com/TheDirepack/Nix-nas/go/internal/hardening"
	"github.com/TheDirepack/Nix-nas/go/internal/lineio"
	"github.com/TheDirepack/Nix-nas/go/internal/nassecrets"
	"github.com/TheDirepack/Nix-nas/go/internal/txn"
)

// configEnv names the Nix-rendered settings file; the wrapper sets it.
const configEnv = "NAS_SECRETS_CONFIG"

func main() {
	if err := hardening.DisableDumps(); err != nil {
		fmt.Fprintln(os.Stderr, "nas-secrets: unable to disable process dumps:", err)
		os.Exit(1)
	}
	os.Exit(int(run()))
}

func run() txn.Exit {
	syscall.Umask(0o077)
	name := ""
	if len(os.Args) > 1 {
		name = os.Args[1]
	}
	if name == "--help" || name == "-h" || name == "help" {
		fmt.Println(nassecrets.Usage)
		return nassecrets.ExitOK
	}
	cmd, ok := nassecrets.ParseCommand(name)
	if !ok || len(os.Args) > 2 {
		fmt.Fprintln(os.Stderr, nassecrets.Usage)
		return nassecrets.ExitUsage
	}
	settings, err := config.Load(os.Getenv(configEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nassecrets.ExitFailure
	}
	if cmd.Coordinated() {
		if code, done := enterCoordinator(settings, name); done {
			return code
		}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range signals {
			code := nassecrets.ExitTerminate
			switch s {
			case syscall.SIGHUP:
				code = nassecrets.ExitHangup
			case syscall.SIGINT:
				code = nassecrets.ExitInterrupt
			}
			cancel(&nassecrets.SignalExit{Code: code})
		}
	}()
	runner := cmdexec.NewOS()
	app := &nassecrets.App{
		S:         settings,
		R:         runner,
		In:        lineio.NewStdin(os.Stdin),
		Out:       os.Stdout,
		Err:       os.Stderr,
		HTTP:      &http.Client{Timeout: 2 * time.Second},
		Escalates: runner.Escalate,
		UID:       os.Getuid(),
		GID:       os.Getgid(),
	}
	return app.Run(ctx, cmd)
}

// enterCoordinator re-executes under nas-operation-run unless a coordinator
// token is already present, in which case it validates the inherited lock.
func enterCoordinator(s *config.Settings, name string) (txn.Exit, bool) {
	runner := s.OperationRunner.String()
	if v := os.Getenv("NAS_OPERATION_RUNNER"); v != "" {
		runner = v
	}
	if st, err := os.Stat(runner); err != nil || st.Mode()&0o111 == 0 { // #nosec G703 -- the coordinator path is operator configuration, executed only if executable
		fmt.Fprintf(os.Stderr, "NAS operation coordinator is unavailable: %s\n", runner)
		return nassecrets.ExitFailure, true
	}
	if os.Getenv("NAS_OPERATION_COORDINATION_TOKEN") != "" {
		c := exec(runner, "--validate-current", "--class", "secrets", "--class", "runtime")
		if c != 0 {
			return c, true
		}
		return 0, false
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nas-secrets cannot locate itself: %v\n", err)
		return nassecrets.ExitFailure, true
	}
	if err := syscall.Exec(runner, coordinatorArgs(runner, self, name), os.Environ()); err != nil { // #nosec -- runner is the pinned coordinator
		fmt.Fprintf(os.Stderr, "NAS operation coordinator is unavailable: %v\n", err)
	}
	return nassecrets.ExitFailure, true
}

func coordinatorArgs(runner, self, name string) []string {
	args := []string{runner, "--action", "nas-secrets:" + name, "--class", "secrets", "--class", "runtime"}
	if name == "activate-stdin" {
		args = append(args, "--forward-termination")
	}
	return append(args, "--", self, name)
}
