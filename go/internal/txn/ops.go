package txn

import (
	"context"
	"fmt"
	"strings"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// PrivilegedFS observes the filesystem the privileged swap operates on.
// Transaction trees live under root-owned 0700 directories that the calling
// administrator cannot traverse, so every observation runs as root.
type PrivilegedFS struct{ Runner cmdexec.Runner }

func (f PrivilegedFS) test(ctx context.Context, flag string, p syspath.Abs) bool {
	res, err := f.Runner.RunRoot(ctx, cmdexec.Root(cmdexec.Test, cmdexec.Word(flag), p))
	return err == nil && res.OK()
}

func (f PrivilegedFS) IsDir(ctx context.Context, p syspath.Abs) bool     { return f.test(ctx, "-d", p) }
func (f PrivilegedFS) IsFile(ctx context.Context, p syspath.Abs) bool    { return f.test(ctx, "-f", p) }
func (f PrivilegedFS) IsSymlink(ctx context.Context, p syspath.Abs) bool { return f.test(ctx, "-L", p) }
func (f PrivilegedFS) Exists(ctx context.Context, p syspath.Abs) bool    { return f.test(ctx, "-e", p) }

func (f PrivilegedFS) Realpath(ctx context.Context, p syspath.Abs) (string, error) {
	res, err := f.Runner.RunRoot(ctx, cmdexec.Root(cmdexec.Realpath, cmdexec.Word("-e"), cmdexec.Word("--"), p).Stdout(cmdexec.Capture))
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", fmt.Errorf("realpath exited %d", res.Code)
	}
	return strings.TrimSuffix(string(res.Stdout), "\n"), nil
}

// StepError carries a failed command's exit status.
type StepError struct {
	Argv []string
	Code int
}

func (e *StepError) Error() string {
	return fmt.Sprintf("%s exited with status %d", strings.Join(e.Argv, " "), e.Code)
}

func (f PrivilegedFS) root(ctx context.Context, c cmdexec.Privileged) error {
	res, err := f.Runner.RunRoot(ctx, c.Stderr(cmdexec.Inherit))
	if err != nil {
		return err
	}
	if !res.OK() {
		return &StepError{Argv: c.Argv(), Code: res.Code}
	}
	return nil
}

func (f PrivilegedFS) Move(ctx context.Context, src, dst syspath.Abs) error {
	return f.root(ctx, cmdexec.Root(cmdexec.Mv, cmdexec.Word("-T"), cmdexec.Word("--"), src, dst))
}

func (f PrivilegedFS) RemoveAll(ctx context.Context, p syspath.Abs) error {
	return f.root(ctx, cmdexec.Root(cmdexec.Rm, cmdexec.Word("-rf"), cmdexec.Word("--"), p))
}

// PrivilegedSystemd runs systemctl as root.
type PrivilegedSystemd struct{ Runner cmdexec.Runner }

func (s PrivilegedSystemd) Show(ctx context.Context, t syspath.Target) (string, error) {
	// --all makes systemctl print an explicit empty Job= when none is queued.
	c := cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("show"), cmdexec.Word("--all"),
		cmdexec.Word("--property=LoadState"), cmdexec.Word("--property=ActiveState"), cmdexec.Word("--property=Job"), t).
		Stdout(cmdexec.Capture)
	res, err := s.Runner.RunRoot(ctx, c)
	if err != nil {
		return "", err
	}
	if !res.OK() {
		return "", &StepError{Argv: c.Argv(), Code: res.Code}
	}
	return string(res.Stdout), nil
}

func (s PrivilegedSystemd) Stop(ctx context.Context, t syspath.Target) error {
	return PrivilegedFS(s).root(ctx, cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("stop"), t))
}

func (s PrivilegedSystemd) Start(ctx context.Context, t syspath.Target) error {
	c := cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("start"), t)
	res, err := s.Runner.RunRoot(ctx, c)
	if err != nil {
		return err
	}
	if !res.OK() {
		return &StepError{Argv: c.Argv(), Code: res.Code}
	}
	return nil
}
