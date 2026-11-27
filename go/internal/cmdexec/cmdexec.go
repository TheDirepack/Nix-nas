// Package cmdexec builds and runs child processes whose argv can hold only
// non-secret values and whose stdin is the only channel for secrets.
//
// secret.Secret has no method that yields a string, so no Arg can carry
// secret bytes. Privileged commands are a separate type that has no stdin at
// all, so sudo can never consume a secret payload.
package cmdexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/secret"
)

// Arg is one argv element. syspath types and Word implement it.
type Arg interface {
	ArgString() string
}

// Word is a literal option or operand. It exists for constants such as
// "--quiet"; do not convert data of unknown provenance.
type Word string

func (w Word) ArgString() string { return string(w) }

// Mode is a file mode rendered in octal for install/chmod.
type Mode uint32

func (m Mode) ArgString() string { return fmt.Sprintf("%04o", uint32(m)) }

// Int renders a non-negative decimal.
type Int int

func (i Int) ArgString() string { return strconv.Itoa(int(i)) }

// Program is a tool resolved on PATH; the Nix wrapper pins PATH.
type Program string

// ArgString lets a program name appear as an operand (env, runuser).
func (p Program) ArgString() string { return string(p) }

// Tools invoked by the KeePass system.
const (
	KeePassXC Program = "keepassxc-cli" // #nosec G101 -- a tool name, not a credential
	Sudo      Program = "sudo"
	Systemctl Program = "systemctl"
	Install   Program = "install"
	Mv        Program = "mv"
	Rm        Program = "rm"
	Test      Program = "test"
	Realpath  Program = "realpath"
	Stat      Program = "stat"
	Ln        Program = "ln"
	Chown     Program = "chown"
	Chmod     Program = "chmod"
	Mktemp    Program = "mktemp"
	Cat       Program = "cat"
	Runuser   Program = "runuser"
	Env       Program = "env"
)

// Output selects what happens to a child stream; the variants are exhaustive.
type Output int

const (
	// Discard sends the stream to /dev/null.
	Discard Output = iota
	// Inherit passes the stream to this process's stream.
	Inherit
	// Capture records the stream in Result.
	Capture
)

// Command is an unprivileged invocation.
type Command struct {
	prog   Program
	args   []Arg
	stdin  *secret.Payload
	stdout Output
	stderr Output
}

// New builds a command; streams default to Discard.
func New(p Program, args ...Arg) Command {
	return Command{prog: p, args: args}
}

// WithStdin attaches the secret payload; only unprivileged commands have it.
func (c Command) WithStdin(p secret.Payload) Command { c.stdin = &p; return c }

// Stdout selects the stdout disposition.
func (c Command) Stdout(o Output) Command { c.stdout = o; return c }

// Stderr selects the stderr disposition.
func (c Command) Stderr(o Output) Command { c.stderr = o; return c }

// Argv renders argv for logging and tests. It never contains secrets.
func (c Command) Argv() []string {
	out := []string{string(c.prog)}
	for _, a := range c.args {
		out = append(out, a.ArgString())
	}
	return out
}

// Privileged is a command that runs as root: directly when this process is
// root, otherwise through sudo. It has no stdin field.
type Privileged struct {
	prog   Program
	args   []Arg
	stdout Output
	stderr Output
}

// Root builds a privileged command.
func Root(p Program, args ...Arg) Privileged { return Privileged{prog: p, args: args} }

// Stdout selects the stdout disposition.
func (c Privileged) Stdout(o Output) Privileged { c.stdout = o; return c }

// Stderr selects the stderr disposition.
func (c Privileged) Stderr(o Output) Privileged { c.stderr = o; return c }

// Argv renders the unprefixed argv.
func (c Privileged) Argv() []string { return New(c.prog, c.args...).Argv() }

// Result is the observed outcome; Stdout/Stderr hold only captured streams.
type Result struct {
	Code   int
	Stdout []byte
	Stderr []byte
}

// OK reports exit status zero.
func (r Result) OK() bool { return r.Code == 0 }

// Runner executes commands. Tests substitute a fake.
type Runner interface {
	Run(ctx context.Context, c Command) (Result, error)
	RunSecret(ctx context.Context, c Command) (secret.Secret, Result, error)
	RunRoot(ctx context.Context, c Privileged) (Result, error)
}

// OS runs real processes.
type OS struct {
	// Escalate prefixes privileged commands with sudo; false when euid is 0.
	Escalate bool
	// NonInteractive uses `sudo -n` so a missing cached authorization fails
	// instead of prompting (setup workers).
	NonInteractive bool
}

// NewOS chooses escalation from the effective uid.
func NewOS() *OS { return &OS{Escalate: os.Geteuid() != 0} }

// Grace bounds how long a cancelled child may run after SIGTERM.
const Grace = 180 * time.Second

// ErrStart wraps a failure to start the child at all.
var ErrStart = errors.New("cmdexec: unable to start")

func stream(o Output, inherit *os.File, buf *bytes.Buffer) io.Writer {
	switch o {
	case Discard:
		return nil
	case Inherit:
		return inherit
	case Capture:
		return buf
	}
	return nil
}

func (r *OS) run(ctx context.Context, argv []string, stdin *secret.Payload, stdout, stderr Output, secretOut bool) (secret.Secret, Result, error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return secret.Secret{}, Result{Code: 127}, fmt.Errorf("%w %s: %w", ErrStart, argv[0], err)
	}
	cmd := exec.CommandContext(ctx, path, argv[1:]...) // #nosec -- argv is built only from Arg values
	cmd.Args[0] = argv[0]
	var outBuf, errBuf bytes.Buffer
	if secretOut {
		stdout = Capture
	}
	cmd.Stdout = stream(stdout, os.Stdout, &outBuf)
	cmd.Stderr = stream(stderr, os.Stderr, &errBuf)
	// SIGTERM lets nas-secrets roll back; SIGKILL follows only after Grace.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = Grace
	var pipe *secret.StdinPipe
	if stdin != nil {
		w, rd, perr := secret.NewStdinPipe()
		if perr != nil {
			return secret.Secret{}, Result{Code: 127}, perr
		}
		pipe = w
		cmd.Stdin = rd
		defer func() { _ = rd.Close() }()
	}
	if err := cmd.Start(); err != nil {
		if pipe != nil {
			_ = pipe.Close()
		}
		return secret.Secret{}, Result{Code: 127}, fmt.Errorf("%w %s: %w", ErrStart, argv[0], err)
	}
	if pipe != nil {
		// EPIPE from a child that exits early is judged by its exit status.
		_ = stdin.Feed(pipe)
	}
	werr := cmd.Wait()
	res := Result{Stderr: errBuf.Bytes()}
	if !secretOut {
		res.Stdout = outBuf.Bytes()
	}
	var exitErr *exec.ExitError
	switch {
	case werr == nil:
	case errors.As(werr, &exitErr):
		res.Code = exitErr.ExitCode()
		if res.Code < 0 {
			res.Code = 128 + int(exitErr.Sys().(syscall.WaitStatus).Signal()) // linux WaitStatus
		}
	default:
		return secret.Secret{}, Result{Code: 127}, werr
	}
	if ctx.Err() != nil {
		return secret.Secret{}, res, ctx.Err()
	}
	if secretOut {
		raw := outBuf.Bytes()
		s := secret.FromBytes(raw)
		return s, res, nil
	}
	return secret.Secret{}, res, nil
}

// Run executes an unprivileged command.
func (r *OS) Run(ctx context.Context, c Command) (Result, error) {
	_, res, err := r.run(ctx, c.Argv(), c.stdin, c.stdout, c.stderr, false)
	return res, err
}

// RunSecret executes c and returns its stdout as a secret.
func (r *OS) RunSecret(ctx context.Context, c Command) (secret.Secret, Result, error) {
	return r.run(ctx, c.Argv(), c.stdin, c.stdout, c.stderr, true)
}

// RunRoot executes a privileged command with stdin bound to /dev/null.
func (r *OS) RunRoot(ctx context.Context, c Privileged) (Result, error) {
	argv := c.Argv()
	if r.Escalate {
		prefix := []string{string(Sudo), "--"}
		if r.NonInteractive {
			prefix = []string{string(Sudo), "-n", "--"}
		}
		argv = append(prefix, argv...)
	}
	_, res, err := r.run(ctx, argv, nil, c.stdout, c.stderr, false)
	return res, err
}
