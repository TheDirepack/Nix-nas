// Package nassecrets implements the nas-secrets command: KeePassXC-backed
// secret initialization, activation into /run, and operator utilities.
package nassecrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"syscall"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/config"
	"github.com/TheDirepack/Nix-nas/go/internal/keepass"
	"github.com/TheDirepack/Nix-nas/go/internal/lineio"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
	"github.com/TheDirepack/Nix-nas/go/internal/txn"
)

// Exit statuses of nas-secrets. The unlock API and setup interpret them.
const (
	ExitOK             txn.Exit = 0
	ExitFailure        txn.Exit = 1
	ExitUsage          txn.Exit = 2
	ExitRefused        txn.Exit = 70
	ExitServiceStart   txn.Exit = 71
	ExitServiceFailed  txn.Exit = 72
	ExitNotReady       txn.Exit = 73
	ExitNotActive      txn.Exit = 74
	ExitManualRecovery          = txn.ExitManualRecovery
	ExitHangup         txn.Exit = 129
	ExitInterrupt      txn.Exit = 130
	ExitTerminate      txn.Exit = 143
)

// Fail is an operator-facing failure with its exit status. The message is
// printed verbatim to stderr and never contains secret values.
type Fail struct {
	Code txn.Exit
	Msg  string
}

func (f *Fail) Error() string { return f.Msg }

func fail(code txn.Exit, format string, args ...any) *Fail {
	return &Fail{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// App carries the process context of one nas-secrets invocation.
type App struct {
	S    *config.Settings
	R    cmdexec.Runner
	In   *lineio.Stdin
	Out  io.Writer
	Err  io.Writer
	HTTP *http.Client
	// Escalates reports whether privileged commands go through sudo.
	Escalates bool
	UID, GID  int
}

func (a *App) say(format string, args ...any)  { _, _ = fmt.Fprintf(a.Out, format+"\n", args...) }
func (a *App) warn(format string, args ...any) { _, _ = fmt.Fprintf(a.Err, format+"\n", args...) }

func (a *App) database() *keepass.Database {
	return &keepass.Database{Path: a.S.Database, KeyFile: a.S.KeyFile, Group: a.S.Group, Runner: a.R}
}

// root runs a privileged command and converts a nonzero status to *Fail.
func (a *App) root(ctx context.Context, c cmdexec.Privileged) error {
	res, err := a.R.RunRoot(ctx, c.Stderr(cmdexec.Inherit))
	if err != nil {
		return fail(ExitFailure, "%s: %v", c.Argv()[0], err)
	}
	if !res.OK() {
		return fail(statusOf(res.Code), "Command failed: %v (status %d)", c.Argv(), res.Code)
	}
	return nil
}

// rootOK runs a privileged predicate such as test or systemctl is-failed.
func (a *App) rootOK(ctx context.Context, c cmdexec.Privileged) bool {
	res, err := a.R.RunRoot(ctx, c)
	return err == nil && res.OK()
}

func (a *App) rootTest(ctx context.Context, flag string, p syspath.Abs) bool {
	return a.rootOK(ctx, cmdexec.Root(cmdexec.Test, cmdexec.Word(flag), p))
}

func statusOf(code int) txn.Exit {
	if code <= 0 || code > 255 {
		return ExitFailure
	}
	return txn.Exit(code)
}

// lock takes the non-blocking nas-secrets flock for the process lifetime.
func (a *App) lock() (*os.File, error) {
	f, err := os.OpenFile(a.S.LockFile.String(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fail(ExitFailure, "Unable to open the NAS secret lock: %v", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec -- fd fits int
		_ = f.Close()
		return nil, fail(ExitFailure, "Another NAS secret operation is already running.")
	}
	return f, nil
}

func (a *App) requireDatabase() error {
	if st, err := os.Stat(a.S.Database.String()); err != nil || !st.Mode().IsRegular() {
		return fail(ExitFailure, "KeePassXC database not found: %s\nCreate or restore the KDBX database, then configure nas.secrets.keepassDatabase.", a.S.Database)
	}
	if a.S.KeyFile != nil {
		if st, err := os.Stat(a.S.KeyFile.String()); err != nil || !st.Mode().IsRegular() {
			return fail(ExitFailure, "KeePassXC key file not found: %s", *a.S.KeyFile)
		}
	}
	return nil
}

// PasswordSource selects how the KeePass password arrives.
type PasswordSource int

const (
	// FromTerminal prompts on stderr with echo disabled.
	FromTerminal PasswordSource = iota
	// FromStdin reads one bounded line from stdin.
	FromStdin
)

// unlock is prompt_unlock: read, bound, then verify with db-info.
func (a *App) unlock(ctx context.Context, src PasswordSource) (*keepass.Session, error) {
	if err := a.requireDatabase(); err != nil {
		return nil, err
	}
	var raw secret.Secret
	var err error
	switch src {
	case FromStdin:
		raw, err = a.In.Line()
		if errors.Is(err, secret.LineMissing) {
			return nil, fail(ExitFailure, "Unable to read the KeePass database password from standard input.")
		}
	case FromTerminal:
		raw, err = a.In.Prompt("KeePass database password: ")
		if errors.Is(err, secret.LineMissing) {
			err = secret.LineEmpty
		}
	}
	switch {
	case errors.Is(err, secret.LineEmpty):
		return nil, fail(ExitFailure, "%s", secret.ErrPasswordEmpty)
	case errors.Is(err, secret.LineTooLong):
		return nil, fail(ExitFailure, "%s", secret.ErrPasswordTooLong)
	case err != nil:
		return nil, fail(ExitFailure, "Unable to read the KeePass database password.")
	}
	pw, err := secret.NewKeePassPassword(raw)
	if err != nil {
		raw.Destroy()
		return nil, fail(ExitFailure, "%s", err)
	}
	sess, err := a.database().Unlock(ctx, pw)
	if err != nil {
		pw.Destroy()
		return nil, fail(ExitFailure, "%s", keepass.WrongPasswordMarker)
	}
	return sess, nil
}

// readStdinLine reads one further bounded line, e.g. a token after the
// password.
func (a *App) readStdinLine(what string) (secret.Secret, error) {
	s, err := a.In.Line()
	if err != nil {
		return secret.Secret{}, fail(ExitFailure, "Unable to read the %s.", what)
	}
	return s, nil
}

func (a *App) expectEOF(context string) error {
	if err := a.In.ExpectEOF(); err != nil {
		return fail(ExitFailure, "Unexpected extra input while %s.", context)
	}
	return nil
}
