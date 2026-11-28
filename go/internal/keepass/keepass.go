// Package keepass drives keepassxc-cli. A Session exists only after the
// database accepted the password, so no entry operation can run against a
// locked database. Entries are a closed enum: callers cannot address
// arbitrary KeePass paths.
package keepass

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// WrongPasswordMarker is the stderr line nas-unlock-api maps to HTTP 401.
const WrongPasswordMarker = "Unable to unlock the KeePassXC database."

// Entry names one managed KeePass item.
type Entry int

// Managed entries.
const (
	AuthentikSecretKey Entry = iota
	AuthentikBootstrapToken
	AuthentikAPIToken
	AuthentikBootstrapPassword
	AuthentikOutpostToken
	StateBundleSigningKey
	GrafanaSecretKey
	NtfyAdminPassword
	NtfyAlertTopic
	NutWebguiServerKey
	ZFSDatasetKey
	VaultwardenOIDCClientSecret
	VaultwardenAdmin
)

// Key is the entry title inside the managed group.
func (e Entry) Key() string {
	switch e {
	case AuthentikSecretKey:
		return "authentik-secret-key"
	case AuthentikBootstrapToken:
		return "authentik-bootstrap-token"
	case AuthentikAPIToken:
		return "authentik-api-token"
	case AuthentikBootstrapPassword:
		return "authentik-bootstrap-password"
	case AuthentikOutpostToken:
		return "authentik-outpost-token"
	case StateBundleSigningKey:
		return "state-bundle-signing-key"
	case GrafanaSecretKey:
		return "grafana-secret-key"
	case NtfyAdminPassword:
		return "ntfy-admin-password"
	case NtfyAlertTopic:
		return "ntfy-alert-topic"
	case NutWebguiServerKey:
		return "nut-webgui-server-key"
	case ZFSDatasetKey:
		return "zfs-dataset-key"
	case VaultwardenOIDCClientSecret:
		return "vaultwarden-oidc-client-secret"
	case VaultwardenAdmin:
		return "vaultwarden-admin"
	}
	panic(fmt.Sprintf("keepass: unknown entry %d", int(e)))
}

// Group is the managed KeePass group name.
type Group struct{ s string }

// NewGroup rejects path separators and control characters.
func NewGroup(s string) (Group, error) {
	n, err := syspath.NewName(s)
	if err != nil {
		return Group{}, fmt.Errorf("invalid KeePass group: %w", err)
	}
	return Group{s: n.String()}, nil
}

func (g Group) ArgString() string { return g.s }

type entryPath struct {
	group Group
	entry Entry
}

func (p entryPath) ArgString() string { return p.group.s + "/" + p.entry.Key() }

// Database is a configured, still locked KDBX.
type Database struct {
	Path    syspath.Abs
	KeyFile *syspath.Abs
	Group   Group
	Runner  cmdexec.Runner
}

// ErrWrongPassword means keepassxc-cli refused the password (or key file).
var ErrWrongPassword = errors.New(WrongPasswordMarker)

func (d *Database) base(sub string, extra ...cmdexec.Arg) []cmdexec.Arg {
	args := []cmdexec.Arg{cmdexec.Word(sub), cmdexec.Word("--quiet")}
	if d.KeyFile != nil {
		args = append(args, cmdexec.Word("--key-file"), *d.KeyFile)
	}
	return append(args, extra...)
}

// Unlock verifies the password with db-info and returns a session that owns
// the password until Close.
func (d *Database) Unlock(ctx context.Context, pw secret.KeePassPassword) (*Session, error) {
	c := cmdexec.New(cmdexec.KeePassXC, d.base("db-info", d.Path)...).WithStdin(secret.Lines(pw))
	res, err := d.Runner.Run(ctx, c)
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, ErrWrongPassword
	}
	return &Session{db: d, pw: pw}, nil
}

// Session is an unlocked database.
type Session struct {
	db *Database
	pw secret.KeePassPassword
}

// Close destroys the password.
func (s *Session) Close() { s.pw.Destroy() }

func (s *Session) cli(sub string, extra ...cmdexec.Arg) cmdexec.Command {
	return cmdexec.New(cmdexec.KeePassXC, s.db.base(sub, extra...)...)
}

func (s *Session) path(e Entry) entryPath { return entryPath{group: s.db.Group, entry: e} }

// EnsureGroup creates the managed group when it is missing.
func (s *Session) EnsureGroup(ctx context.Context) error {
	ls := s.cli("ls", s.db.Path, s.db.Group).WithStdin(secret.Lines(s.pw))
	if res, err := s.db.Runner.Run(ctx, ls); err == nil && res.OK() {
		return nil
	} else if ctx.Err() != nil {
		return ctx.Err()
	}
	mk := s.cli("mkdir", s.db.Path, s.db.Group).WithStdin(secret.Lines(s.pw))
	res, err := s.db.Runner.Run(ctx, mk)
	if err != nil || !res.OK() {
		return fmt.Errorf("Unable to ensure KeePassXC group: %s", s.db.Group.s)
	}
	return nil
}

// ErrListing means the group listing failed; callers must not guess.
var ErrListing = errors.New("Unable to inspect the KeePassXC secret group.")

// Has reports exact membership in the flattened group listing.
func (s *Session) Has(ctx context.Context, e Entry) (bool, error) {
	c := s.cli("ls", cmdexec.Word("--flatten"), s.db.Path, s.db.Group).WithStdin(secret.Lines(s.pw)).Stdout(cmdexec.Capture)
	res, err := s.db.Runner.Run(ctx, c)
	if err != nil || !res.OK() {
		return false, ErrListing
	}
	for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
		if string(line) == e.Key() {
			return true, nil
		}
	}
	return false, nil
}

// Store adds or replaces the entry's password attribute.
func (s *Session) Store(ctx context.Context, e Entry, value secret.Holder) error {
	present, err := s.Has(ctx, e)
	if err != nil {
		return err
	}
	sub := "add"
	if present {
		sub = "edit"
	}
	payload := secret.Lines(s.pw, value)
	defer payload.Destroy()
	c := s.cli(sub, cmdexec.Word("-p"), s.db.Path, s.path(e)).WithStdin(payload)
	res, err := s.db.Runner.Run(ctx, c)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("Unable to store KeePassXC entry: %s", s.path(e).ArgString())
	}
	return nil
}

// Remove deletes the entry when present; a failed delete is an error.
func (s *Session) Remove(ctx context.Context, e Entry) error {
	present, err := s.Has(ctx, e)
	if err != nil || !present {
		return err
	}
	c := s.cli("rm", s.db.Path, s.path(e)).WithStdin(secret.Lines(s.pw))
	res, err := s.db.Runner.Run(ctx, c)
	if err != nil || !res.OK() {
		return fmt.Errorf("Unable to remove KeePassXC entry: %s", s.path(e).ArgString())
	}
	return nil
}

// Get returns the entry's protected password; empty values are errors.
func (s *Session) Get(ctx context.Context, e Entry) (secret.Secret, error) {
	c := s.cli("show", cmdexec.Word("--show-protected"), cmdexec.Word("-a"), cmdexec.Word("Password"), s.db.Path, s.path(e)).
		WithStdin(secret.Lines(s.pw))
	value, res, err := s.db.Runner.RunSecret(ctx, c)
	if err != nil || !res.OK() {
		value.Destroy()
		return secret.Secret{}, fmt.Errorf("Unable to retrieve KeePassXC entry: %s", s.path(e).ArgString())
	}
	value = secret.TrimTrailingNewlines(value)
	if value.Empty() {
		return secret.Secret{}, fmt.Errorf("KeePassXC returned an empty password for: %s", s.path(e).ArgString())
	}
	return value, nil
}

// GetOptional returns ok=false when the entry is absent.
func (s *Session) GetOptional(ctx context.Context, e Entry) (secret.Secret, bool, error) {
	present, err := s.Has(ctx, e)
	if err != nil || !present {
		return secret.Secret{}, false, err
	}
	v, err := s.Get(ctx, e)
	return v, err == nil, err
}
