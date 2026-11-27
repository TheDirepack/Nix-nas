// Package setupkp implements the KeePass steps of first-start setup that
// nas-setup (Python) delegates over stdin: the password strength floor, the
// salted journal verifier and the never-replace database guard.
package setupkp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// DecryptionTimeMS is the KDBX key-derivation target for a new database.
const DecryptionTimeMS = 1000

// Mode selects verify-only or verify-or-create; the set is closed.
type Mode int

const (
	// VerifyOnly requires an existing database that opens.
	VerifyOnly Mode = iota
	// Create opens an existing database or creates one.
	Create
)

// DatasetEncryption is the caller's observation of the managed dataset;
// Unknown is treated as encrypted.
type DatasetEncryption int

const (
	// DatasetUnencrypted means no ZFS key depends on this database.
	DatasetUnencrypted DatasetEncryption = iota
	// DatasetEncrypted means the dataset key lives in the database.
	DatasetEncrypted
	// DatasetUnknown fails closed.
	DatasetUnknown
)

func (d DatasetEncryption) holdsKey() bool {
	switch d {
	case DatasetUnencrypted:
		return false
	case DatasetEncrypted, DatasetUnknown:
		return true
	}
	return true
}

// Outcome is what happened to the database.
type Outcome int

const (
	// Existing means an existing database opened with the password.
	Existing Outcome = iota
	// Created means a new database was created.
	Created
)

func (o Outcome) String() string {
	switch o {
	case Existing:
		return "existing"
	case Created:
		return "created"
	}
	return "unknown"
}

// Database is the never-replace database guard.
type Database struct {
	Path    syspath.Abs
	KeyFile *syspath.Abs
	Owner   syspath.Account
	Runner  cmdexec.Runner
	// Escalate reports whether root commands need sudo.
	Escalate bool
	Now      func() time.Time
	Progress io.Writer
}

// Result reports the outcome and any preserved previous database.
type Result struct {
	Outcome   Outcome      `json:"-"`
	Name      string       `json:"result"`
	Preserved *syspath.Abs `json:"-"`
	Kept      string       `json:"preserved,omitempty"`
}

var usersGroup = syspath.MustAccount("users")

func (d *Database) root(ctx context.Context, c cmdexec.Privileged) error {
	if d.Escalate {
		res, err := d.Runner.Run(ctx, cmdexec.New(cmdexec.Sudo, cmdexec.Word("-n"), cmdexec.Word("-v")).Stderr(cmdexec.Capture))
		if err != nil || !res.OK() {
			detail := "cached sudo authorization is unavailable"
			if len(res.Stderr) > 0 {
				detail = string(res.Stderr)
			}
			return fmt.Errorf("Privileged setup authorization expired: %s", detail)
		}
	}
	res, err := d.Runner.RunRoot(ctx, c.Stderr(cmdexec.Capture))
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("Command failed: %v: %s", c.Argv(), res.Stderr)
	}
	return nil
}

// asOwner runs keepassxc-cli as the database owner, as nas-setup's
// admin_command does: directly when already that user, through runuser when
// root, otherwise refused.
func (d *Database) asOwner(args ...cmdexec.Arg) (cmdexec.Command, error) {
	current, err := user.Current()
	if err != nil {
		return cmdexec.Command{}, err
	}
	if current.Username == d.Owner.String() {
		return cmdexec.New(cmdexec.KeePassXC, args...), nil
	}
	if os.Geteuid() != 0 {
		return cmdexec.Command{}, fmt.Errorf("Run nas-setup as %s or root, not %s", d.Owner, current.Username)
	}
	owner, err := user.Lookup(d.Owner.String())
	if err != nil {
		return cmdexec.Command{}, fmt.Errorf("Configured local administrator does not exist: %s", d.Owner)
	}
	home, err := syspath.NewAbs(owner.HomeDir)
	if err != nil {
		return cmdexec.Command{}, err
	}
	prefix := []cmdexec.Arg{cmdexec.Word("-u"), d.Owner, cmdexec.Word("--"), cmdexec.Env,
		cmdexec.Word("--chdir=" + home.String()), cmdexec.Word("HOME=" + home.String()),
		cmdexec.Word("PATH=" + os.Getenv("PATH")), cmdexec.KeePassXC}
	return cmdexec.New(cmdexec.Runuser, append(prefix, args...)...), nil
}

func (d *Database) keyArgs(flag string) []cmdexec.Arg {
	if d.KeyFile == nil {
		return nil
	}
	return []cmdexec.Arg{cmdexec.Word(flag), *d.KeyFile}
}

func (d *Database) opens(ctx context.Context, pw secret.KeePassPassword) error {
	args := append([]cmdexec.Arg{cmdexec.Word("db-info"), cmdexec.Word("--quiet")}, d.keyArgs("--key-file")...)
	c, err := d.asOwner(append(args, d.Path)...)
	if err != nil {
		return err
	}
	res, err := d.Runner.Run(ctx, c.WithStdin(secret.Lines(pw)))
	if err != nil {
		return err
	}
	if !res.OK() {
		return errors.New("Unable to unlock the KeePassXC database.")
	}
	return nil
}

// create is reachable only with a password that passed the strength floor.
func (d *Database) create(ctx context.Context, pw secret.StrongKeePassPassword) error {
	args := []cmdexec.Arg{cmdexec.Word("db-create"), cmdexec.Word("--quiet"), cmdexec.Word("--set-password"),
		cmdexec.Word("--decryption-time"), cmdexec.Int(DecryptionTimeMS)}
	args = append(args, d.keyArgs("--set-key-file")...)
	c, err := d.asOwner(append(args, d.Path)...)
	if err != nil {
		return err
	}
	payload := secret.Lines(pw, pw)
	defer payload.Destroy()
	res, err := d.Runner.Run(ctx, c.WithStdin(payload))
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("KeePassXC could not create %s", d.Path)
	}
	return nil
}

func present(p syspath.Abs) (os.FileInfo, bool) {
	st, err := os.Lstat(p.String())
	return st, err == nil
}

// VerifyOrCreate never deletes an existing database. It refuses to replace
// one while the managed dataset may hold its key, and otherwise moves it
// aside with mv --no-clobber before creating a fresh one.
func (d *Database) VerifyOrCreate(ctx context.Context, mode Mode, pw secret.KeePassPassword, admin *secret.Secret, dataset DatasetEncryption) (Result, error) {
	if err := d.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-d"), cmdexec.Word("-m"), cmdexec.Mode(0o700),
		cmdexec.Word("-o"), d.Owner, cmdexec.Word("-g"), usersGroup, d.Path.Dir())); err != nil {
		return Result{}, err
	}
	st, exists := present(d.Path)
	if exists && (st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular()) {
		return Result{}, fmt.Errorf("KeePass database path is not a regular file: %s", d.Path)
	}
	var preserved *syspath.Abs
	if exists {
		switch mode {
		case VerifyOnly:
			if err := d.opens(ctx, pw); err != nil {
				return Result{}, err
			}
			return result(Existing, nil), nil
		case Create:
		}
		if dataset.holdsKey() {
			// The encrypted dataset's only key lives in this database; a
			// fresh database would silently orphan the data.
			if err := d.opens(ctx, pw); err != nil {
				return Result{}, fmt.Errorf("The managed ZFS dataset is already encrypted with a key held in %s. "+
					"Setup never replaces that database; retry with its password.", d.Path)
			}
			return result(Existing, nil), nil
		}
		now := time.Now
		if d.Now != nil {
			now = d.Now
		}
		aside, err := syspath.NewAbs(d.Path.String() + ".replaced-" + now().UTC().Format("20060102T150405Z"))
		if err != nil {
			return Result{}, err
		}
		if err := d.root(ctx, cmdexec.Root(cmdexec.Mv, cmdexec.Word("--no-clobber"), cmdexec.Word("--"), d.Path, aside)); err != nil {
			return Result{}, err
		}
		if _, still := present(d.Path); still {
			return Result{}, fmt.Errorf("Unable to move the existing KeePassXC database aside to %s", aside)
		}
		if d.Progress != nil {
			_, _ = fmt.Fprintf(d.Progress, "nas-setup: kept the previous KeePassXC database as %s\n", aside)
		}
		preserved = &aside
	}
	switch mode {
	case VerifyOnly:
		return Result{}, fmt.Errorf("KeePass database does not exist: %s", d.Path)
	case Create:
	}
	strong, err := secret.NewStrongKeePassPassword(pw, admin)
	if err != nil {
		return Result{}, err
	}
	if err := d.create(ctx, strong); err != nil {
		return Result{}, err
	}
	if _, ok := present(d.Path); !ok {
		return Result{}, fmt.Errorf("KeePassXC did not create %s", d.Path)
	}
	if err := d.opens(ctx, pw); err != nil {
		return Result{}, err
	}
	return result(Created, preserved), nil
}

func result(o Outcome, preserved *syspath.Abs) Result {
	r := Result{Outcome: o, Name: o.String(), Preserved: preserved}
	if preserved != nil {
		r.Kept = preserved.String()
	}
	return r
}

// StoredVerifier decodes a journal verifier leniently; malformed fields
// simply never match.
type StoredVerifier struct {
	Algorithm any `json:"algorithm"`
	Salt      any `json:"salt"`
	Digest    any `json:"digest"`
}

// Verifier converts to the typed record; non-string fields become empty.
func (s StoredVerifier) Verifier() secret.Verifier {
	str := func(v any) string {
		if t, ok := v.(string); ok {
			return t
		}
		return ""
	}
	return secret.Verifier{Algorithm: str(s.Algorithm), Salt: str(s.Salt), Digest: str(s.Digest)}
}
