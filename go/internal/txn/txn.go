// Package txn swaps the live secret tree for a staged one with phase-aware
// rollback.
//
// The transaction is a typestate: Begin yields *Staged, whose only forward
// move is Swap; only *Swapped can Commit, and only Committed evidence can
// authorize post-commit work. Commit before swap, swap after swap and
// commit after rollback therefore do not compile. Each state value is
// single-use; reusing a consumed value panics rather than silently acting
// on a stale phase.
//
// Phases: initialized -> observing -> stopping -> stopped -> old-moved ->
// new-installed -> committing -> committed. Rollback before old-moved may
// restart prior consumers directly; after old-moved it must restore the
// previous tree first. Once commit starts deleting the previous tree,
// rollback is unsafe and cleanup failures surface as ExitManualRecovery
// with the new tree authoritative.
package txn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// Exit is a process exit status; the type makes out-of-range values
// unrepresentable.
type Exit uint8

// ExitManualRecovery means rollback or commit cleanup could not complete.
const ExitManualRecovery Exit = 125

// FS isolates transaction filesystem operations for fault injection.
type FS interface {
	IsDir(ctx context.Context, p syspath.Abs) bool
	IsFile(ctx context.Context, p syspath.Abs) bool
	IsSymlink(ctx context.Context, p syspath.Abs) bool
	Exists(ctx context.Context, p syspath.Abs) bool
	Realpath(ctx context.Context, p syspath.Abs) (string, error)
	// Move must refuse an existing destination.
	Move(ctx context.Context, src, dst syspath.Abs) error
	RemoveAll(ctx context.Context, p syspath.Abs) error
}

// Systemd observes and controls the protected target.
type Systemd interface {
	Show(ctx context.Context, t syspath.Target) (string, error)
	Stop(ctx context.Context, t syspath.Target) error
	Start(ctx context.Context, t syspath.Target) error
}

// Phase is the transaction phase; the variants are exhaustive.
type Phase int

// Phases.
const (
	PhaseInitialized Phase = iota
	PhaseObserving
	PhaseStopping
	PhaseStopped
	PhaseOldMoved
	PhaseNewInstalled
	PhaseCommitting
	PhaseCommitted
	PhaseCommitCleanupFailed
	PhaseRolledBack
	PhaseRollbackIncomplete
)

func (p Phase) String() string {
	switch p {
	case PhaseInitialized:
		return "initialized"
	case PhaseObserving:
		return "observing"
	case PhaseStopping:
		return "stopping"
	case PhaseStopped:
		return "stopped"
	case PhaseOldMoved:
		return "old-moved"
	case PhaseNewInstalled:
		return "new-installed"
	case PhaseCommitting:
		return "committing"
	case PhaseCommitted:
		return "committed"
	case PhaseCommitCleanupFailed:
		return "commit-cleanup-failed"
	case PhaseRolledBack:
		return "rolled-back"
	case PhaseRollbackIncomplete:
		return "rollback-incomplete"
	}
	return "unknown"
}

// TargetState is a stable observation of the protected target.
type TargetState int

// Stable target states.
const (
	TargetActive TargetState = iota
	TargetInactive
	TargetFailed
)

type priorActivity int

const (
	priorUnknown priorActivity = iota
	priorActive
	priorInactive
)

// Plan is a lexically validated set of transaction paths.
type Plan struct {
	root, stage, previous syspath.Abs
	dir                   *syspath.Abs
	target                syspath.Target
}

// Root is the live secret tree.
func (p Plan) Root() syspath.Abs { return p.root }

// Stage is the staged tree that Swap installs.
func (p Plan) Stage() syspath.Abs { return p.stage }

// NewPlan checks absolute, non-root, pairwise-disjoint paths and an optional
// transaction directory that directly contains stage and previous.
func NewPlan(root, stage, previous syspath.Abs, dir *syspath.Abs, target syspath.Target) (Plan, error) {
	for _, v := range []syspath.Abs{root, stage, previous} {
		if v.IsZero() {
			return Plan{}, errors.New("nas-secret-transaction: paths must be absolute")
		}
		if v.IsRoot() {
			return Plan{}, errors.New("nas-secret-transaction: refusing to operate on filesystem root")
		}
	}
	switch {
	case root.Overlaps(stage):
		return Plan{}, errors.New("nas-secret-transaction: secret root and staged tree must be disjoint")
	case root.Overlaps(previous):
		return Plan{}, errors.New("nas-secret-transaction: secret root and previous tree must be disjoint")
	case stage.Overlaps(previous):
		return Plan{}, errors.New("nas-secret-transaction: staged and previous trees must be disjoint")
	}
	if dir != nil {
		switch {
		case dir.IsRoot():
			return Plan{}, errors.New("nas-secret-transaction: refusing filesystem root as transaction directory")
		case root.Overlaps(*dir):
			return Plan{}, errors.New("nas-secret-transaction: transaction directory must be disjoint from the live secret root")
		case stage.Dir() != *dir || previous.Dir() != *dir:
			return Plan{}, errors.New("nas-secret-transaction: staged and previous trees must be direct children of the transaction directory")
		}
	}
	return Plan{root: root, stage: stage, previous: previous, dir: dir, target: target}, nil
}

type core struct {
	fs     FS
	sd     Systemd
	log    io.Writer
	plan   Plan
	phase  Phase
	prior  priorActivity
	swap   bool
	oldMv  bool
	newIn  bool
	commit bool
}

func (c *core) logf(format string, args ...any) error {
	msg := "nas-secret-transaction: " + fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintln(c.log, msg)
	return errors.New(msg)
}

// Staged is a validated, not yet swapped transaction.
type Staged struct {
	c    *core
	used bool
}

// Swapped has installed the staged tree; it must Commit or Abort.
type Swapped struct {
	c    *core
	used bool
}

// Committed is evidence that the new tree is authoritative.
type Committed struct{ c *core }

// RolledBack is the final outcome of an aborted transaction.
type RolledBack struct {
	// Status is the primary status, or ExitManualRecovery when rollback was
	// incomplete or the transaction ended "successfully" without commit.
	Status Exit
	// Complete reports whether every prior tree was restored.
	Complete bool
}

// Begin verifies that the plan's parents resolve physically to the same
// paths (no symlink traversal) through the privileged filesystem.
func Begin(ctx context.Context, fs FS, sd Systemd, log io.Writer, p Plan) (*Staged, error) {
	c := &core{fs: fs, sd: sd, log: log, plan: p, phase: PhaseInitialized}
	for _, v := range []syspath.Abs{p.root, p.stage, p.previous} {
		physical, err := fs.Realpath(ctx, v.Dir())
		if err != nil || physical != v.Dir().String() {
			return nil, c.logf("parent path is missing or traverses a symlink: %s", v)
		}
	}
	if p.dir != nil {
		d := *p.dir
		if !fs.IsDir(ctx, d) || fs.IsSymlink(ctx, d) {
			return nil, c.logf("transaction directory must be a real directory: %s", d)
		}
		physical, err := fs.Realpath(ctx, d)
		if err != nil {
			return nil, c.logf("transaction directory cannot be resolved safely: %s", d)
		}
		if physical != d.String() {
			return nil, c.logf("transaction directory traverses a symlink: %s", d)
		}
	}
	return &Staged{c: c}, nil
}

// Phase reports the current phase.
func (s *Staged) Phase() Phase { return s.c.phase }

func (c *core) observe(ctx context.Context) (TargetState, error) {
	out, err := c.sd.Show(ctx, c.plan.target)
	if err != nil {
		return 0, c.logf("protected target status is unavailable")
	}
	load, active, job := "", "", "unavailable"
	for line := range strings.SplitSeq(out, "\n") {
		switch {
		case strings.HasPrefix(line, "LoadState="):
			load = strings.TrimPrefix(line, "LoadState=")
		case strings.HasPrefix(line, "ActiveState="):
			active = strings.TrimPrefix(line, "ActiveState=")
		case strings.HasPrefix(line, "Job="):
			job = strings.TrimPrefix(line, "Job=")
		}
	}
	if load == "loaded" && job == "" {
		switch active {
		case "active":
			return TargetActive, nil
		case "inactive":
			return TargetInactive, nil
		case "failed":
			return TargetFailed, nil
		}
	}
	return 0, c.logf("protected target has no stable loaded state (load=%s, active=%s, job=%s)", load, active, job)
}

func (c *core) stopTarget(ctx context.Context) error {
	stopErr := c.sd.Stop(ctx, c.plan.target)
	// Neither stop success nor a failed status query proves consumers stopped.
	state, err := c.observe(ctx)
	if err != nil {
		return err
	}
	switch state {
	case TargetInactive, TargetFailed:
		return nil
	case TargetActive:
	}
	return c.logf("protected target remains active after stop (status %v)", stopErr)
}

// Swap stops the target, moves the live tree aside and installs the stage.
// On error the transaction must still be aborted through s.Abort.
func (s *Staged) Swap(ctx context.Context) (*Swapped, error) {
	if s.used {
		panic("txn: Swap on a consumed Staged")
	}
	c := s.c
	if c.phase != PhaseInitialized {
		return nil, c.logf("invalid swap phase: %s", c.phase)
	}
	fs, p := c.fs, c.plan
	switch {
	case !fs.IsDir(ctx, p.stage):
		return nil, c.logf("staged tree is unavailable: %s", p.stage)
	case fs.IsSymlink(ctx, p.stage):
		return nil, c.logf("staged tree must not be a symlink: %s", p.stage)
	case !fs.IsFile(ctx, p.stage.Join(readyName)):
		return nil, c.logf("staged tree is missing its ready marker")
	case fs.IsSymlink(ctx, p.stage.Join(readyName)):
		return nil, c.logf("staged ready marker must not be a symlink")
	}
	if fs.Exists(ctx, p.root) {
		if !fs.IsDir(ctx, p.root) {
			return nil, c.logf("live secret root is not a directory: %s", p.root)
		}
		if fs.IsSymlink(ctx, p.root) {
			return nil, c.logf("live secret root must not be a symlink: %s", p.root)
		}
	}
	if fs.Exists(ctx, p.previous) {
		return nil, c.logf("previous tree already exists: %s", p.previous)
	}
	c.swap = true
	c.phase = PhaseObserving
	state, err := c.observe(ctx)
	if err != nil {
		return nil, err
	}
	c.prior = priorInactive
	if state == TargetActive {
		c.prior = priorActive
	}
	c.phase = PhaseStopping
	if err := c.stopTarget(ctx); err != nil {
		return nil, err
	}
	c.phase = PhaseStopped
	if fs.IsDir(ctx, p.root) {
		if err := fs.Move(ctx, p.root, p.previous); err != nil {
			return nil, err
		}
		c.oldMv = true
	}
	c.phase = PhaseOldMoved
	if err := fs.Move(ctx, p.stage, p.root); err != nil {
		return nil, err
	}
	c.newIn = true
	c.phase = PhaseNewInstalled
	ready := p.root.Join(readyName)
	if !fs.IsDir(ctx, p.root) || fs.IsSymlink(ctx, p.root) || !fs.IsFile(ctx, ready) || fs.IsSymlink(ctx, ready) {
		return nil, c.logf("installed secret tree failed post-swap validation")
	}
	s.used = true
	return &Swapped{c: c}, nil
}

var readyName = syspath.MustName("ready")

func (c *core) removeDirectory(ctx context.Context) error {
	if c.plan.dir == nil {
		return nil
	}
	return c.fs.RemoveAll(ctx, *c.plan.dir)
}

func (c *core) rollback(ctx context.Context) bool {
	fs, p := c.fs, c.plan
	if c.commit {
		_ = c.logf("refusing rollback after commit")
		return false
	}
	failed := false
	if !c.swap {
		if fs.RemoveAll(ctx, p.stage) != nil {
			failed = true
		}
		// Deleting the transaction directory also deletes the stage; do it
		// only after the stage is gone so a failure keeps every copy.
		if !failed && c.removeDirectory(ctx) != nil {
			failed = true
		}
		if failed {
			c.phase = PhaseRollbackIncomplete
			retained := p.stage.String()
			if p.dir != nil {
				retained = p.dir.String()
			}
			_ = c.logf("pre-swap cleanup was incomplete; retained recovery tree %s; staged tree %s", retained, p.stage)
			return false
		}
		c.phase = PhaseRolledBack
		return true
	}
	// An unknown prior state or unconfirmed stop must preserve every tree.
	if c.prior == priorUnknown || c.stopTarget(ctx) != nil {
		failed = true
	} else {
		if c.newIn && fs.RemoveAll(ctx, p.root) != nil {
			failed = true
		}
		if !failed && c.oldMv {
			if fs.IsDir(ctx, p.previous) && !fs.IsSymlink(ctx, p.previous) {
				if fs.Move(ctx, p.previous, p.root) != nil {
					failed = true
				}
			} else {
				_ = c.logf("previous secret tree disappeared or became unsafe during rollback: %s", p.previous)
				failed = true
			}
		}
		// Starting before the restore is known good would run consumers
		// against a half-rolled-back tree.
		if c.prior == priorActive && !failed {
			ready := p.root.Join(readyName)
			if fs.IsFile(ctx, ready) && !fs.IsSymlink(ctx, ready) {
				if c.sd.Start(ctx, p.target) != nil {
					failed = true
				}
			} else {
				_ = c.logf("restored secret tree is not ready; protected target remains stopped")
				failed = true
			}
		}
		if !failed && fs.RemoveAll(ctx, p.stage) != nil {
			failed = true
		}
		if !failed && c.removeDirectory(ctx) != nil {
			failed = true
		}
	}
	if failed {
		c.phase = PhaseRollbackIncomplete
		_ = c.logf("rollback was incomplete; inspect systemd and %s", p.root)
		candidates := []syspath.Abs{p.stage, p.previous}
		if p.dir != nil {
			candidates = append([]syspath.Abs{*p.dir}, candidates...)
		}
		for _, r := range candidates {
			if fs.Exists(ctx, r) || fs.IsSymlink(ctx, r) {
				_ = c.logf("retained recovery tree %s", r)
			}
		}
		return false
	}
	c.phase = PhaseRolledBack
	return true
}

func (c *core) abort(primary Exit) RolledBack {
	// Rollback must run to completion even after the caller's context was
	// cancelled by a signal.
	ctx := context.Background()
	if !c.rollback(ctx) {
		_ = c.logf("manual recovery required; primary status %d", primary)
		return RolledBack{Status: ExitManualRecovery}
	}
	if primary == 0 {
		_ = c.logf("transaction exited successfully without commit; rolled back")
		return RolledBack{Status: ExitManualRecovery, Complete: true}
	}
	return RolledBack{Status: primary, Complete: true}
}

// Abort rolls back a transaction whose Swap was never attempted or failed.
func (s *Staged) Abort(primary Exit) RolledBack {
	if s.used {
		panic("txn: Abort on a consumed Staged")
	}
	s.used = true
	return s.c.abort(primary)
}

// Phase reports the current phase.
func (w *Swapped) Phase() Phase { return w.c.phase }

// Abort rolls back an installed but uncommitted tree.
func (w *Swapped) Abort(primary Exit) RolledBack {
	if w.used {
		panic("txn: Abort on a consumed Swapped")
	}
	w.used = true
	return w.c.abort(primary)
}

// CommitCleanupError means the new tree is authoritative but the previous
// tree or transaction directory could not be removed.
type CommitCleanupError struct{ msg string }

func (e *CommitCleanupError) Error() string { return e.msg }

// Commit makes the new tree authoritative and removes the previous one.
// The returned evidence is valid even with a cleanup error.
func (w *Swapped) Commit(ctx context.Context) (Committed, *CommitCleanupError) {
	if w.used {
		panic("txn: Commit on a consumed Swapped")
	}
	w.used = true
	c := w.c
	if c.phase != PhaseNewInstalled || !c.newIn || c.commit {
		panic("txn: Commit outside the new-installed phase")
	}
	c.commit = true
	c.phase = PhaseCommitting
	if c.fs.RemoveAll(ctx, c.plan.previous) != nil {
		c.phase = PhaseCommitCleanupFailed
		return Committed{c: c}, &CommitCleanupError{msg: c.logf("committed new tree but could not remove previous tree").Error()}
	}
	if c.removeDirectory(ctx) != nil {
		c.phase = PhaseCommitCleanupFailed
		return Committed{c: c}, &CommitCleanupError{msg: c.logf("committed new tree but could not remove transaction directory").Error()}
	}
	c.phase = PhaseCommitted
	return Committed{c: c}, nil
}

// Phase reports the final phase.
func (k Committed) Phase() Phase { return k.c.phase }

// Root is the now-authoritative live tree.
func (k Committed) Root() syspath.Abs { return k.c.plan.root }
