package nassecrets

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/keepass"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
	"github.com/TheDirepack/Nix-nas/go/internal/txn"
)

func ownerOf(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Uid)
	}
	return -1
}

func groupOf(st os.FileInfo) int {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(sys.Gid)
	}
	return -1
}

// Command is one nas-secrets subcommand; the set is closed.
type Command int

// Subcommands.
const (
	CmdInit Command = iota
	CmdAdoptAuthentikBootstrapStdin
	CmdActivate
	CmdActivateStdin
	CmdActivateSetupStdin
	CmdStatus
	CmdStop
	CmdSetAuthentikToken
	CmdSetAuthentikTokenStdin
	CmdSetAuthentikRuntimeStdin
	CmdRetireAuthentikBootstrapStdin
	CmdCheckAuthentikToken
	CmdShowNtfyPassword
	CmdShowZFSKey
	CmdShowZFSKeyStdin
	CmdShowAuthentikBootstrap
)

var commandNames = map[string]Command{
	"init":                             CmdInit,
	"adopt-authentik-bootstrap-stdin":  CmdAdoptAuthentikBootstrapStdin,
	"activate":                         CmdActivate,
	"activate-stdin":                   CmdActivateStdin,
	"activate-setup-stdin":             CmdActivateSetupStdin,
	"status":                           CmdStatus,
	"stop":                             CmdStop,
	"set-authentik-token":              CmdSetAuthentikToken,
	"set-authentik-token-stdin":        CmdSetAuthentikTokenStdin,
	"set-authentik-runtime-stdin":      CmdSetAuthentikRuntimeStdin,
	"retire-authentik-bootstrap-stdin": CmdRetireAuthentikBootstrapStdin,
	"check-authentik-token":            CmdCheckAuthentikToken,
	"show-ntfy-password":               CmdShowNtfyPassword,
	"show-zfs-key":                     CmdShowZFSKey,
	"show-zfs-key-stdin":               CmdShowZFSKeyStdin,
	"show-authentik-bootstrap":         CmdShowAuthentikBootstrap,
}

// Usage is the historical usage line.
const Usage = "Usage: nas-secrets {init|adopt-authentik-bootstrap-stdin|activate|activate-stdin|status|stop|set-authentik-token|set-authentik-token-stdin|set-authentik-runtime-stdin|retire-authentik-bootstrap-stdin|check-authentik-token|show-ntfy-password|show-zfs-key|show-zfs-key-stdin|show-authentik-bootstrap}"

// ParseCommand maps argv[1].
func ParseCommand(name string) (Command, bool) {
	c, ok := commandNames[name]
	return c, ok
}

// Coordinated reports whether the command mutates appliance state and so
// must run under the operation coordinator.
func (c Command) Coordinated() bool {
	switch c {
	case CmdInit, CmdAdoptAuthentikBootstrapStdin, CmdActivate, CmdActivateStdin, CmdActivateSetupStdin, CmdStop,
		CmdSetAuthentikToken, CmdSetAuthentikTokenStdin, CmdSetAuthentikRuntimeStdin, CmdRetireAuthentikBootstrapStdin:
		return true
	case CmdStatus, CmdCheckAuthentikToken, CmdShowNtfyPassword, CmdShowZFSKey, CmdShowZFSKeyStdin, CmdShowAuthentikBootstrap:
		return false
	}
	return true
}

// Run dispatches a parsed command.
func (a *App) Run(ctx context.Context, c Command) txn.Exit {
	var err error
	switch c {
	case CmdActivate:
		return a.Activate(ctx, RuntimeMode{}, FromTerminal)
	case CmdActivateStdin:
		return a.Activate(ctx, RuntimeMode{}, FromStdin)
	case CmdActivateSetupStdin:
		return a.Activate(ctx, SetupMode{}, FromStdin)
	case CmdInit:
		err = a.cmdInit(ctx)
	case CmdAdoptAuthentikBootstrapStdin:
		err = a.cmdAdopt(ctx)
	case CmdStatus:
		a.cmdStatus(ctx)
	case CmdStop:
		err = a.cmdStop(ctx)
	case CmdSetAuthentikToken:
		err = a.cmdSetToken(ctx, FromTerminal)
	case CmdSetAuthentikTokenStdin:
		err = a.cmdSetToken(ctx, FromStdin)
	case CmdSetAuthentikRuntimeStdin:
		err = a.cmdSetRuntime(ctx)
	case CmdRetireAuthentikBootstrapStdin:
		err = a.cmdRetire(ctx)
	case CmdCheckAuthentikToken:
		err = a.cmdCheckToken(ctx)
	case CmdShowNtfyPassword:
		err = a.cmdShow(ctx, FromTerminal, keepass.NtfyAdminPassword, "", "\n")
	case CmdShowZFSKey:
		err = a.cmdShow(ctx, FromTerminal, keepass.ZFSDatasetKey, "", "")
		_, _ = a.Err.Write([]byte("\n"))
	case CmdShowZFSKeyStdin:
		err = a.cmdShowZFSStdin(ctx)
	case CmdShowAuthentikBootstrap:
		err = a.cmdShow(ctx, FromTerminal, keepass.AuthentikBootstrapPassword, "Username: akadmin\nPassword: ", "\n")
	}
	if err != nil {
		return a.report(ctx, err)
	}
	return ExitOK
}

func (a *App) locked(ctx context.Context, src PasswordSource, group bool) (*os.File, *keepass.Session, error) {
	lock, err := a.lock()
	if err != nil {
		return nil, nil, err
	}
	sess, err := a.unlock(ctx, src)
	if err != nil {
		_ = lock.Close()
		return nil, nil, err
	}
	if group {
		if err := sess.EnsureGroup(ctx); err != nil {
			sess.Close()
			_ = lock.Close()
			return nil, nil, formatFail(err)
		}
	}
	return lock, sess, nil
}

func (a *App) storeRandomIfMissing(ctx context.Context, s *keepass.Session, e keepass.Entry, label string, n int) error {
	has, err := s.Has(ctx, e)
	if err != nil {
		return formatFail(err)
	}
	if has {
		a.say("KeePassXC item already exists: %s", label)
		return nil
	}
	v, err := secret.RandomHex(n)
	if err != nil {
		return formatFail(err)
	}
	defer v.Secret().Destroy()
	if err := s.Store(ctx, e, v); err != nil {
		return formatFail(err)
	}
	a.say("Created KeePassXC item: %s", label)
	return nil
}

func (a *App) cmdInit(ctx context.Context) error {
	lock, s, err := a.locked(ctx, FromTerminal, true)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	type item struct {
		on    bool
		e     keepass.Entry
		label string
		n     int
	}
	f := a.S.Features
	first := []item{
		{true, keepass.AuthentikSecretKey, "Authentik secret key", 64},
		{true, keepass.AuthentikBootstrapToken, "Authentik bootstrap token", 32},
	}
	for _, it := range first {
		if err := a.storeRandomIfMissing(ctx, s, it.e, it.label, it.n); err != nil {
			return err
		}
	}
	has, err := s.Has(ctx, keepass.AuthentikAPIToken)
	if err != nil {
		return formatFail(err)
	}
	if !has {
		token, err := s.Get(ctx, keepass.AuthentikBootstrapToken)
		if err != nil {
			return formatFail(err)
		}
		value, err := secret.NewOpaque(token, "Authentik bootstrap token")
		if err != nil {
			return formatFail(err)
		}
		err = s.Store(ctx, keepass.AuthentikAPIToken, value)
		token.Destroy()
		if err != nil {
			return formatFail(err)
		}
		a.say("Created KeePassXC item: Authentik NAS API token (initially the bootstrap token)")
	}
	rest := []item{
		{true, keepass.AuthentikBootstrapPassword, "Authentik bootstrap administrator password", 24},
		{true, keepass.StateBundleSigningKey, "NAS state bundle HMAC signing key", 32},
		{f.Observability && f.Grafana, keepass.GrafanaSecretKey, "Grafana signing and data-source secret key", 32},
		{f.Ntfy, keepass.NtfyAdminPassword, "ntfy administrator password", 24},
		{f.Ntfy, keepass.NtfyAlertTopic, "ntfy private alert topic", 16},
		{f.NutWeb, keepass.NutWebguiServerKey, "NUT Web GUI session signing key", 32},
		{f.ZFSEncryption, keepass.ZFSDatasetKey, "ZFS native encryption key", 32},
		{f.Vaultwarden, keepass.VaultwardenOIDCClientSecret, "Vaultwarden Authentik OIDC client secret", 32},
		{f.Vaultwarden, keepass.VaultwardenAdmin, "Vaultwarden admin token", 32},
	}
	for _, it := range rest {
		if !it.on {
			continue
		}
		if err := a.storeRandomIfMissing(ctx, s, it.e, it.label, it.n); err != nil {
			return err
		}
	}
	a.say("\nSecret initialization complete. Human identity and access policy remain in Authentik.\nRun: nas-secrets activate")
	return nil
}

func (a *App) cmdAdopt(ctx context.Context) error {
	lock, s, err := a.locked(ctx, FromStdin, true)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	rawKey, err := a.readStdinLine("Authentik bootstrap secret key")
	if err != nil {
		return err
	}
	defer rawKey.Destroy()
	rawToken, err := a.readStdinLine("Authentik bootstrap token")
	if err != nil {
		return err
	}
	defer rawToken.Destroy()
	rawPassword, err := a.readStdinLine("Authentik bootstrap password")
	if err != nil {
		return err
	}
	defer rawPassword.Destroy()
	if err := a.expectEOF("adopting Authentik bootstrap authority"); err != nil {
		return err
	}
	key, err := secret.NewHexKey(rawKey, 128, "Authentik bootstrap secret key")
	if err != nil {
		return formatFail(err)
	}
	token, err := secret.NewHexKey(rawToken, 64, "Authentik bootstrap token")
	if err != nil {
		return formatFail(err)
	}
	password, err := secret.NewHexKey(rawPassword, 48, "Authentik bootstrap password")
	if err != nil {
		return formatFail(err)
	}
	for _, step := range []struct {
		e keepass.Entry
		v secret.Holder
	}{
		{keepass.AuthentikSecretKey, key},
		{keepass.AuthentikBootstrapToken, token},
		{keepass.AuthentikAPIToken, token},
		{keepass.AuthentikBootstrapPassword, password},
	} {
		if err := s.Store(ctx, step.e, step.v); err != nil {
			return formatFail(err)
		}
	}
	a.say("Adopted the running first-boot Authentik authority.")
	return nil
}

func (a *App) cmdStatus(ctx context.Context) {
	if st, err := os.Stat(a.S.SecretRoot.Join(syspath.MustName("ready")).String()); err == nil && st.Mode().IsRegular() {
		a.say("Runtime secrets: active")
	} else {
		a.say("Runtime secrets: inactive")
	}
	if st, err := os.Stat(a.S.Database.String()); err == nil && st.Mode().IsRegular() {
		a.say("KeePassXC database: configured")
	} else {
		a.say("KeePassXC database: missing")
	}
	for _, u := range []string{"authentik.service", "nas-v2-timer-identity-sync-0.timer"} {
		_, _ = a.R.Run(ctx, cmdexec.New(cmdexec.Systemctl, cmdexec.Word("is-active"), syspath.MustUnit(u)).Stdout(cmdexec.Inherit))
	}
	if _, err := os.Stat(a.S.SecretRoot.Join(syspath.MustName("authentik-token-warning")).String()); err == nil {
		a.say("Authentik API token: WARNING — bootstrap token still in use")
	} else {
		a.say("Authentik API token: scoped-token warning not present")
	}
}

func (a *App) cmdStop(ctx context.Context) error {
	lock, err := a.lock()
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	// Path-triggered Caddy selection must see the locked state before
	// stopping units can publish changes that trigger reconciliation.
	if err := a.removeFile(ctx, a.S.SecretRoot.Join(syspath.MustName("ready"))); err != nil {
		return err
	}
	if err := a.root(ctx, cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("stop"), a.S.ProtectedTarget)); err != nil {
		return err
	}
	if a.Escalates {
		err = (txn.PrivilegedFS{Runner: a.R}).RemoveAll(ctx, a.S.SecretRoot)
	} else {
		err = (txn.DirectFS{}).RemoveAll(ctx, a.S.SecretRoot)
	}
	if err != nil {
		return err
	}
	a.say("Protected services stopped and runtime secrets removed. KeePassXC was not modified.")
	return nil
}

func (a *App) cmdCheckToken(ctx context.Context) error {
	lock, s, err := a.locked(ctx, FromTerminal, false)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	api, err := s.Get(ctx, keepass.AuthentikAPIToken)
	if err != nil {
		return formatFail(err)
	}
	defer api.Destroy()
	has, err := s.Has(ctx, keepass.AuthentikBootstrapToken)
	if err != nil {
		return formatFail(err)
	}
	if !has {
		a.say("Authentik bootstrap token is retired; runtime API token is separate.")
		return nil
	}
	bootstrap, err := s.Get(ctx, keepass.AuthentikBootstrapToken)
	if err != nil {
		return formatFail(err)
	}
	defer bootstrap.Destroy()
	if bootstrap.Equal(api) {
		return fail(ExitFailure, "WARNING: Authentik runtime API token is still the bootstrap token.")
	}
	a.say("Authentik runtime API token differs from the bootstrap token.")
	return nil
}

func (a *App) readToken(src PasswordSource, label, what string) (secret.APIToken, error) {
	var raw secret.Secret
	var err error
	switch src {
	case FromTerminal:
		raw, err = a.In.Prompt("Authentik API token: ")
	case FromStdin:
		raw, err = a.In.Line()
	}
	if err != nil && !errors.Is(err, secret.LineEmpty) {
		return secret.APIToken{}, fail(ExitFailure, "Unable to read the %s from standard input.", what)
	}
	t, terr := secret.NewAPIToken(raw, label)
	if terr != nil {
		raw.Destroy()
		return secret.APIToken{}, formatFail(terr)
	}
	return t, nil
}

func (a *App) cmdSetToken(ctx context.Context, src PasswordSource) error {
	lock, s, err := a.locked(ctx, src, true)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	token, err := a.readToken(src, "Authentik API token", "Authentik API token")
	if err != nil {
		return err
	}
	defer token.Secret().Destroy()
	if src == FromStdin {
		if err := a.expectEOF("setting the Authentik API token"); err != nil {
			return err
		}
	}
	if err := s.Store(ctx, keepass.AuthentikAPIToken, token); err != nil {
		return formatFail(err)
	}
	if src == FromStdin {
		a.say("Authentik API token stored.")
	} else {
		a.say("Authentik API token stored. Run nas-secrets activate to stage it.")
	}
	return nil
}

func (a *App) cmdSetRuntime(ctx context.Context) error {
	lock, s, err := a.locked(ctx, FromStdin, true)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	token, err := a.readToken(FromStdin, "Authentik API token", "Authentik API token")
	if err != nil {
		return err
	}
	defer token.Secret().Destroy()
	outpost, err := a.readToken(FromStdin, "Authentik outpost token", "Authentik outpost token")
	if err != nil {
		return err
	}
	defer outpost.Secret().Destroy()
	if err := a.expectEOF("setting the Authentik runtime tokens"); err != nil {
		return err
	}
	if err := s.Store(ctx, keepass.AuthentikOutpostToken, outpost); err != nil {
		return formatFail(err)
	}
	if err := s.Store(ctx, keepass.AuthentikAPIToken, token); err != nil {
		return formatFail(err)
	}
	a.say("Authentik runtime tokens stored.")
	return nil
}

func (a *App) cmdRetire(ctx context.Context) error {
	lock, s, err := a.locked(ctx, FromStdin, false)
	if err != nil {
		return err
	}
	defer func() { s.Close(); _ = lock.Close() }()
	for _, e := range []keepass.Entry{keepass.AuthentikBootstrapToken, keepass.AuthentikBootstrapPassword} {
		if err := s.Remove(ctx, e); err != nil {
			return formatFail(err)
		}
	}
	a.say("Authentik bootstrap credentials removed. Run nas-secrets activate to remove runtime artifacts.")
	return nil
}

func (a *App) cmdShow(ctx context.Context, src PasswordSource, e keepass.Entry, prefix, suffix secret.Lit) error {
	s, err := a.unlock(ctx, src)
	if err != nil {
		return err
	}
	defer s.Close()
	v, err := s.Get(ctx, e)
	if err != nil {
		return formatFail(err)
	}
	defer v.Destroy()
	o, err := secret.NewOpaque(v, e.Key())
	if err != nil {
		return formatFail(err)
	}
	return secret.DiscloseToStdout(prefix, o, suffix)
}

func (a *App) cmdShowZFSStdin(ctx context.Context) error {
	s, err := a.unlock(ctx, FromStdin)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.expectEOF("showing the ZFS dataset key"); err != nil {
		return err
	}
	v, err := s.Get(ctx, keepass.ZFSDatasetKey)
	if err != nil {
		return formatFail(err)
	}
	defer v.Destroy()
	o, err := secret.NewOpaque(v, "zfs-dataset-key")
	if err != nil {
		return formatFail(err)
	}
	return secret.DiscloseToStdout("", o, "")
}
