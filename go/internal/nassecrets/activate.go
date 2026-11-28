package nassecrets

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/hostfs"
	"github.com/TheDirepack/Nix-nas/go/internal/keepass"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
	"github.com/TheDirepack/Nix-nas/go/internal/txn"
)

// Mode is the activation mode. It is sealed: only SetupMode and RuntimeMode
// exist, and only RuntimeMode can carry post-setup authority.
type Mode interface{ sealedMode() }

// SetupMode is activate-setup-stdin: first start, regenerated boot
// environment stays authoritative, explicit identity start sequence.
type SetupMode struct{}

// RuntimeMode is activate / activate-stdin.
type RuntimeMode struct{}

func (SetupMode) sealedMode()   {}
func (RuntimeMode) sealedMode() {}

// postSetup is evidence that first-start setup completed. Only
// detectPostSetup constructs it and only RuntimeMode calls that, so setup
// activation cannot rotate the boot key, link the unlocked environment or
// retire boot-side credentials.
type postSetup struct {
	retireBootEnvironment bool
}

var (
	unitAuthentik       = syspath.MustUnit("authentik.service")
	unitAuthentikWorker = syspath.MustUnit("authentik-worker.service")
	unitAuthentikMig    = syspath.MustUnit("authentik-migrate.service")
	unitCaddy           = syspath.MustUnit("caddy.service")
	unitPostgres        = syspath.MustUnit("postgresql.service")
	unitPostgresSetup   = syspath.MustUnit("postgresql-setup.service")
	unitOutpost         = syspath.MustUnit("nas-authentik-proxy-outpost.service")
	identityUnits       = []syspath.Unit{unitAuthentik, unitAuthentikWorker, unitCaddy}

	accRoot          = syspath.MustAccount("root")
	accAuthentik     = syspath.MustAccount("authentik")
	accGrafana       = syspath.MustAccount("grafana")
	accObservability = syspath.MustAccount("nas-observability")
)

func (a *App) detectPostSetup(ctx context.Context, _ RuntimeMode) *postSetup {
	if !a.rootTest(ctx, "-e", a.S.SetupState) {
		return nil
	}
	return &postSetup{}
}

// staged is one file in the user-private staging directory and its
// root-owned destination.
type staged struct {
	dir, name    string
	owner, group syspath.Account
}

// activation holds the state of one activate run.
type activation struct {
	a       *App
	mode    Mode
	post    *postSetup
	sess    *keepass.Session
	local   *os.Root
	localAt syspath.Abs
	files   []staged
	outpost bool
	held    []secret.Holder
}

func (v *activation) keep(h secret.Holder) { v.held = append(v.held, h) }

// stage writes a validated secret into the private staging tree.
func (v *activation) stage(dir, name string, h secret.Holder, owner, group syspath.Account) error {
	if err := secret.WriteNewPrivateFile(v.local, dir+"/"+name, h); err != nil {
		return fail(ExitFailure, "Unable to stage %s/%s: %v", dir, name, err)
	}
	v.files = append(v.files, staged{dir: dir, name: name, owner: owner, group: group})
	return nil
}

func (v *activation) get(ctx context.Context, e keepass.Entry) (secret.Secret, error) {
	s, err := v.sess.Get(ctx, e)
	if err != nil {
		return secret.Secret{}, fail(ExitFailure, "%s", err)
	}
	v.keep(s)
	return s, nil
}

func (v *activation) optional(ctx context.Context, e keepass.Entry) (secret.Secret, bool, error) {
	s, ok, err := v.sess.GetOptional(ctx, e)
	if err != nil {
		return secret.Secret{}, false, fail(ExitFailure, "%s", err)
	}
	v.keep(s)
	return s, ok, nil
}

func formatFail(err error) error { return fail(ExitFailure, "%s", err) }

// Activate is command_activate. It returns the process exit status.
func (a *App) Activate(ctx context.Context, mode Mode, src PasswordSource) txn.Exit {
	return a.activate(ctx, mode, src)
}

// report prints an operator-facing failure and returns its status.
func (a *App) report(ctx context.Context, err error) txn.Exit {
	var f *Fail
	switch {
	case errors.As(err, &f):
		a.warn("%s", f.Msg)
		return f.Code
	case ctx.Err() != nil:
		var sig *SignalExit
		if errors.As(context.Cause(ctx), &sig) {
			return sig.Code
		}
		return ExitTerminate
	default:
		var step *txn.StepError
		if errors.As(err, &step) {
			return statusOf(step.Code)
		}
		return ExitFailure
	}
}

// SignalExit is the cancellation cause for HUP/INT/TERM.
type SignalExit struct{ Code txn.Exit }

func (s *SignalExit) Error() string { return "interrupted by signal" }

func (a *App) finish(r txn.RolledBack) txn.Exit {
	if !r.Complete {
		a.warn("Secret activation failed and rollback was incomplete.")
	}
	return r.Status
}

func (a *App) privateRuntimeBase(ctx context.Context) (syspath.Abs, error) {
	stagingRoot := a.S.RuntimeRoot.Join(syspath.MustName("staging"))
	base := stagingRoot.Join(syspath.MustName(strconv.Itoa(a.UID)))
	if !a.Escalates {
		if err := hostfs.Mkdir(stagingRoot, 0, 0, 0o711); err != nil {
			return syspath.Abs{}, err
		}
		if err := hostfs.Mkdir(base, a.UID, a.GID, 0o700); err != nil {
			return syspath.Abs{}, err
		}
	} else {
		if err := a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-d"), cmdexec.Word("-m"), cmdexec.Mode(0o711),
			cmdexec.Word("-o"), accRoot, cmdexec.Word("-g"), accRoot, stagingRoot)); err != nil {
			return syspath.Abs{}, err
		}
		if err := a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-d"), cmdexec.Word("-m"), cmdexec.Mode(0o700),
			cmdexec.Word("-o"), cmdexec.Int(a.UID), cmdexec.Word("-g"), cmdexec.Int(a.GID), base)); err != nil {
			return syspath.Abs{}, err
		}
	}
	st, err := os.Lstat(base.String())
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || ownerOf(st) != a.UID || st.Mode().Perm()&0o077 != 0 {
		return syspath.Abs{}, fail(ExitRefused, "Refusing to stage secrets: a private user runtime directory is unavailable: %s", base)
	}
	return base, nil
}

func (a *App) transactionDir(ctx context.Context) (syspath.Abs, error) {
	txRoot := a.S.RuntimeRoot.Join(syspath.MustName("transactions"))
	if !a.Escalates {
		if err := hostfs.Mkdir(txRoot, 0, 0, 0o700); err != nil {
			return syspath.Abs{}, err
		}
		dir, err := os.MkdirTemp(txRoot.String(), "transaction.")
		if err != nil {
			return syspath.Abs{}, err
		}
		return syspath.NewAbs(dir)
	}
	if err := a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-d"), cmdexec.Word("-m"), cmdexec.Mode(0o700),
		cmdexec.Word("-o"), accRoot, cmdexec.Word("-g"), accRoot, txRoot)); err != nil {
		return syspath.Abs{}, err
	}
	res, err := a.R.RunRoot(ctx, cmdexec.Root(cmdexec.Mktemp, cmdexec.Word("-d"),
		cmdexec.Word(txRoot.String()+"/transaction.XXXXXX")).Stdout(cmdexec.Capture).Stderr(cmdexec.Inherit))
	if err != nil || !res.OK() {
		return syspath.Abs{}, fail(ExitFailure, "Unable to create the secret transaction directory.")
	}
	txDir, err := syspath.NewAbs(strings.TrimSuffix(string(res.Stdout), "\n"))
	if err != nil || txDir.Dir() != txRoot {
		return syspath.Abs{}, fail(ExitFailure, "mktemp returned an unexpected transaction directory.")
	}
	return txDir, nil
}

func (a *App) activate(ctx context.Context, mode Mode, src PasswordSource) txn.Exit {
	lock, err := a.lock()
	if err != nil {
		return a.report(ctx, err)
	}
	defer func() { _ = lock.Close() }()
	sess, err := a.unlock(ctx, src)
	if err != nil {
		return a.report(ctx, err)
	}
	defer sess.Close()

	base, err := a.privateRuntimeBase(ctx)
	if err != nil {
		return a.report(ctx, err)
	}
	localDir, err := os.MkdirTemp(base.String(), "nas-secrets.")
	if err != nil {
		return a.report(ctx, fail(ExitFailure, "Unable to create the staging directory: %v", err))
	}
	defer func() { _ = os.RemoveAll(localDir) }()
	localAt, err := syspath.NewAbs(localDir)
	if err != nil {
		return a.report(ctx, formatFail(err))
	}
	if st, err := os.Lstat(localDir); err != nil || st.Mode().Perm() != 0o700 {
		return a.report(ctx, fail(ExitRefused, "Refusing to stage secrets: temporary directory is not mode 0700."))
	}
	localRoot, err := os.OpenRoot(localDir)
	if err != nil {
		return a.report(ctx, fail(ExitFailure, "Unable to open the staging directory: %v", err))
	}
	defer func() { _ = localRoot.Close() }()

	txDir, err := a.transactionDir(ctx)
	if err != nil {
		return a.report(ctx, err)
	}
	plan, err := txn.NewPlan(a.S.SecretRoot, txDir.Join(syspath.MustName("new")), txDir.Join(syspath.MustName("previous")), &txDir, a.S.ProtectedTarget)
	if err != nil {
		return a.report(ctx, formatFail(err))
	}
	var fs txn.FS = txn.DirectFS{}
	if a.Escalates {
		fs = txn.PrivilegedFS{Runner: a.R}
	}
	staged, err := txn.Begin(ctx, fs, txn.PrivilegedSystemd{Runner: a.R}, a.Err, plan)
	if err != nil {
		// The transaction never owned the directory.
		_ = fs.RemoveAll(context.WithoutCancel(ctx), txDir)
		return a.report(ctx, err)
	}

	v := &activation{a: a, mode: mode, sess: sess, local: localRoot, localAt: localAt}
	defer func() { secret.DestroyAll(v.held...) }()

	if err := v.prepare(ctx); err != nil {
		return a.finish(staged.Abort(a.report(ctx, err)))
	}
	if err := v.install(ctx, plan.Stage()); err != nil {
		return a.finish(staged.Abort(a.report(ctx, err)))
	}
	v2Units, err := a.v2StartUnits(ctx)
	if err != nil {
		return a.finish(staged.Abort(a.report(ctx, err)))
	}
	swapped, err := staged.Swap(ctx)
	if err != nil {
		return a.finish(staged.Abort(a.report(ctx, err)))
	}
	if err := v.startServices(ctx, swapped, v2Units); err != nil {
		return a.finish(swapped.Abort(a.report(ctx, err)))
	}
	committed, cleanupErr := swapped.Commit(ctx)
	if cleanupErr != nil {
		return ExitManualRecovery
	}
	if err := v.afterCommit(ctx, committed); err != nil {
		return a.report(ctx, err)
	}
	a.say("Runtime service secrets activated. Authentik remains the identity source of truth.")
	return ExitOK
}

// prepare renders every runtime file into the private stage.
func (v *activation) prepare(ctx context.Context) error {
	a := v.a
	for _, d := range []string{"authentik", "vaultwarden", "zfs", "observability", "power", "state"} {
		if err := v.local.Mkdir(d, 0o700); err != nil {
			return fail(ExitFailure, "Unable to create staging directory %s: %v", d, err)
		}
	}
	if rm, ok := v.mode.(RuntimeMode); ok {
		v.post = a.detectPostSetup(ctx, rm)
	}
	if v.post != nil {
		if err := v.rotateBootKey(ctx, v.post); err != nil {
			return err
		}
	}

	rawKey, err := v.get(ctx, keepass.AuthentikSecretKey)
	if err != nil {
		return err
	}
	rawBootToken, hasBootToken, err := v.optional(ctx, keepass.AuthentikBootstrapToken)
	if err != nil {
		return err
	}
	rawBootPassword, hasBootPassword, err := v.optional(ctx, keepass.AuthentikBootstrapPassword)
	if err != nil {
		return err
	}
	rawAPI, err := v.get(ctx, keepass.AuthentikAPIToken)
	if err != nil {
		return err
	}
	rawOutpost, hasOutpost, err := v.optional(ctx, keepass.AuthentikOutpostToken)
	if err != nil {
		return err
	}
	key, err := secret.NewHexKey(rawKey, 128, "Authentik secret key")
	if err != nil {
		return formatFail(err)
	}
	api, err := secret.NewAtom(rawAPI, "Authentik API token", 20, 4096)
	if err != nil {
		return formatFail(err)
	}
	var outpost secret.Atom
	if hasOutpost {
		if outpost, err = secret.NewAtom(rawOutpost, "Authentik outpost token", 20, 4096); err != nil {
			return formatFail(err)
		}
	}
	var bootToken secret.HexKey
	var bootPassword secret.Atom
	if hasBootToken || hasBootPassword {
		if bootToken, err = secret.NewHexKey(rawBootToken, 64, "Authentik bootstrap token"); err != nil {
			return formatFail(err)
		}
		if bootPassword, err = secret.NewAtom(rawBootPassword, "Authentik bootstrap password", 20, 4096); err != nil {
			return formatFail(err)
		}
	}
	env := []secret.Part{secret.Lit("AUTHENTIK_SECRET_KEY="), key, secret.Lit("\n")}
	if hasBootToken {
		env = append(env,
			secret.Lit("AUTHENTIK_BOOTSTRAP_TOKEN="), bootToken, secret.Lit("\n"),
			secret.Lit("AUTHENTIK_BOOTSTRAP_PASSWORD="), bootPassword, secret.Lit("\n"),
			secret.Lit("AUTHENTIK_BOOTSTRAP_EMAIL='"+a.S.BootstrapEmail.String()+"'\n"))
	}
	envFile := secret.Join(env...)
	v.keep(envFile)
	steps := []func() error{
		func() error { return v.stage("authentik", "environment", envFile, accAuthentik, accAuthentik) },
		func() error { return v.stage("authentik", "api-token", api, accRoot, accRoot) },
	}
	if hasOutpost {
		v.outpost = true
		steps = append(steps, func() error { return v.stage("authentik", "outpost-token", outpost, accRoot, accRoot) })
	}
	if hasBootToken {
		steps = append(steps, func() error { return v.stage("authentik", "bootstrap-token", bootToken, accRoot, accRoot) })
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	rawState, err := v.get(ctx, keepass.StateBundleSigningKey)
	if err != nil {
		return err
	}
	stateKey, err := secret.NewHexKey(rawState, 64, "State bundle signing key")
	if err != nil {
		return formatFail(err)
	}
	if err := v.stage("state", "bundle-signing-key", stateKey, accRoot, accRoot); err != nil {
		return err
	}
	if hasBootToken && api.Secret().Equal(bootToken.Secret()) {
		warning := secret.Join(secret.Lit("The Authentik runtime API token is still the bootstrap token. Create a scoped service-account token, store it with `nas-secrets set-authentik-token`, and activate secrets again.\n"))
		if err := secret.WriteNewPrivateFile(v.local, "authentik-token-warning", warning); err != nil {
			return fail(ExitFailure, "Unable to stage the token warning: %v", err)
		}
		v.files = append(v.files, staged{dir: "", name: "authentik-token-warning", owner: accRoot, group: accRoot})
		a.warn("WARNING: Authentik runtime API token is still the bootstrap token.")
	}
	return v.prepareOptional(ctx)
}

func (v *activation) prepareOptional(ctx context.Context) error {
	f := v.a.S.Features
	if f.Observability && f.Grafana {
		raw, err := v.get(ctx, keepass.GrafanaSecretKey)
		if err != nil {
			return err
		}
		key, err := secret.NewAtom(raw, "Grafana secret key", 20, 4096)
		if err != nil {
			return formatFail(err)
		}
		if err := v.stage("observability", "grafana-secret-key", key, accGrafana, accGrafana); err != nil {
			return err
		}
	}
	if f.Ntfy {
		rawPw, err := v.get(ctx, keepass.NtfyAdminPassword)
		if err != nil {
			return err
		}
		rawTopic, err := v.get(ctx, keepass.NtfyAlertTopic)
		if err != nil {
			return err
		}
		pw, err := secret.NewAtom(rawPw, "ntfy administrator password", 20, 4096)
		if err != nil {
			return formatFail(err)
		}
		topic, err := secret.NewNtfyTopic(rawTopic)
		if err != nil {
			return formatFail(err)
		}
		hash, err := secret.Bcrypt(pw)
		if err != nil {
			return formatFail(err)
		}
		v.keep(hash)
		env := secret.Join(secret.Lit("NTFY_AUTH_USERS=admin:"), hash, secret.Lit(":admin\nNTFY_AUTH_DEFAULT_ACCESS=deny-all\nNTFY_ENABLE_LOGIN=true\n"))
		v.keep(env)
		for _, step := range []func() error{
			func() error { return v.stage("observability", "ntfy-environment", env, accRoot, accRoot) },
			func() error { return v.stage("observability", "ntfy-topic", topic, accObservability, accObservability) },
			func() error {
				return v.stage("observability", "ntfy-admin-password", pw, accObservability, accObservability)
			},
		} {
			if err := step(); err != nil {
				return err
			}
		}
	}
	if f.NutWeb {
		raw, err := v.get(ctx, keepass.NutWebguiServerKey)
		if err != nil {
			return err
		}
		key, err := secret.NewOpaque(raw, "NUT Web GUI server key")
		if err != nil {
			return formatFail(err)
		}
		if err := v.stage("power", "nut-webgui-server-key", key, accRoot, accRoot); err != nil {
			return err
		}
	}
	if f.ZFSEncryption {
		raw, err := v.get(ctx, keepass.ZFSDatasetKey)
		if err != nil {
			return err
		}
		key, err := secret.NewOpaque(raw, "ZFS dataset key")
		if err != nil {
			return formatFail(err)
		}
		if err := v.stage("zfs", "dataset-key", key, accRoot, accRoot); err != nil {
			return err
		}
	}
	if f.Vaultwarden {
		rawClient, err := v.get(ctx, keepass.VaultwardenOIDCClientSecret)
		if err != nil {
			return err
		}
		rawAdmin, err := v.get(ctx, keepass.VaultwardenAdmin)
		if err != nil {
			return err
		}
		client, err := secret.NewAtom(rawClient, "Vaultwarden OIDC client secret", 8, 4096)
		if err != nil {
			return formatFail(err)
		}
		admin, err := secret.NewAtom(rawAdmin, "Vaultwarden administrator token", 8, 4096)
		if err != nil {
			return formatFail(err)
		}
		hash, err := secret.Argon2idPHC(admin)
		if err != nil {
			return formatFail(err)
		}
		v.keep(hash)
		env := secret.Join(secret.Lit("ADMIN_TOKEN='"), hash, secret.Lit("'\nSSO_CLIENT_SECRET='"), client, secret.Lit("'\n"))
		v.keep(env)
		if err := v.stage("vaultwarden", "environment", env, accRoot, accRoot); err != nil {
			return err
		}
	}
	return nil
}

// rotateBootKey replaces the Authentik key that setup adopted from a
// plaintext first-boot file, before that file is retired. A symlinked
// runtime environment means this boot still uses the file.
func (v *activation) rotateBootKey(ctx context.Context, post *postSetup) error {
	a := v.a
	bootEnv := a.S.BootstrapAuthentikDir.Join(syspath.MustName("environment"))
	if !a.rootTest(ctx, "-e", bootEnv) || a.rootTest(ctx, "-L", a.S.AuthentikRuntimeEnvironmentFile) {
		return nil
	}
	st, err := os.Stat(a.S.Database.String())
	if err != nil {
		return fail(ExitFailure, "Unable to inspect the KeePassXC database: %v", err)
	}

	if err := v.sess.EnsureGroup(ctx); err != nil {
		return formatFail(err)
	}
	key, err := secret.RandomHex(64)
	if err != nil {
		return formatFail(err)
	}
	v.keep(key)
	if err := v.sess.Store(ctx, keepass.AuthentikSecretKey, key); err != nil {
		return formatFail(err)
	}
	// KeePassXC saves by replacing the file; a root activation must not take
	// the database away from its administrator owner.
	if !a.Escalates {
		if err := hostfs.RestoreFileMetadata(a.S.Database, ownerOf(st), groupOf(st), uint32(st.Mode().Perm())); err != nil {
			return err
		}
	} else {
		owner := cmdexec.Word(strconv.Itoa(ownerOf(st)) + ":" + strconv.Itoa(groupOf(st)))
		if err := a.root(ctx, cmdexec.Root(cmdexec.Chown, cmdexec.Word("--"), owner, a.S.Database)); err != nil {
			return err
		}
		if err := a.root(ctx, cmdexec.Root(cmdexec.Chmod, cmdexec.Word("--"), cmdexec.Mode(st.Mode().Perm()), a.S.Database)); err != nil {
			return err
		}
	}
	post.retireBootEnvironment = true
	a.say("Rotated the Authentik secret key held in KeePassXC; the first-boot copy will be removed.")
	return nil
}

func (v *activation) install(ctx context.Context, rootStage syspath.Abs) error {
	a := v.a
	f := a.S.Features
	if a.Escalates {
		if res, err := a.R.Run(ctx, cmdexec.New(cmdexec.Sudo, cmdexec.Word("-v")).Stderr(cmdexec.Inherit)); err != nil || !res.OK() {
			return fail(ExitFailure, "sudo authorization is unavailable.")
		}
	}
	mkdir := func(name string, mode cmdexec.Mode, group syspath.Account) error {
		target := rootStage
		if name != "" {
			target = rootStage.Join(syspath.MustName(name))
		}
		if !a.Escalates {
			gid, err := hostfs.GroupID(group)
			if err != nil {
				return err
			}
			return hostfs.Mkdir(target, 0, gid, uint32(mode))
		}
		return a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-d"), cmdexec.Word("-m"), mode,
			cmdexec.Word("-o"), accRoot, cmdexec.Word("-g"), group, target))
	}
	dirs := []func() error{
		func() error { return mkdir("", 0o711, accRoot) },
		func() error { return mkdir("authentik", 0o750, accAuthentik) },
		func() error { return mkdir("state", 0o700, accRoot) },
	}
	if f.Vaultwarden {
		dirs = append(dirs, func() error { return mkdir("vaultwarden", 0o700, accRoot) })
	}
	if f.ZFSEncryption {
		dirs = append(dirs, func() error { return mkdir("zfs", 0o700, accRoot) })
	}
	if f.Observability || f.Ntfy {
		dirs = append(dirs, func() error { return mkdir("observability", 0o750, accObservability) })
	}
	if f.NutWeb {
		dirs = append(dirs, func() error { return mkdir("power", 0o700, accRoot) })
	}
	for _, d := range dirs {
		if err := d(); err != nil {
			return err
		}
	}
	var root *os.Root
	if !a.Escalates {
		var err error
		root, err = hostfs.OpenRoot(rootStage)
		if err != nil {
			return err
		}
		defer root.Close()
	}
	for _, file := range v.files {
		rel := file.name
		if file.dir != "" {
			rel = file.dir + "/" + file.name
		}
		if root != nil {
			uid, uidErr := hostfs.UserID(file.owner)
			gid, gidErr := hostfs.GroupID(file.group)
			if err := errors.Join(uidErr, gidErr); err != nil {
				return err
			}
			if err := secret.InstallPrivateFile(v.local, rel, root, rel, uid, gid, false); err != nil {
				return err
			}
			continue
		}
		st, err := v.local.Lstat(rel)
		if err != nil || !st.Mode().IsRegular() {
			return fail(ExitFailure, "Refusing to install a non-regular or symlink secret source: %s/%s", v.localAt, rel)
		}
		src, _ := syspath.NewAbs(v.localAt.String() + "/" + rel)
		dst, _ := syspath.NewAbs(rootStage.String() + "/" + rel)
		if err := a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-m"), cmdexec.Mode(0o400),
			cmdexec.Word("-o"), file.owner, cmdexec.Word("-g"), file.group, cmdexec.Word("--"), src, dst)); err != nil {
			return err
		}
	}
	if root != nil {
		return secret.InstallPrivateFile(nil, "", root, "ready", 0, 0, false)
	}
	return a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-m"), cmdexec.Mode(0o400), cmdexec.Word("-o"), accRoot,
		cmdexec.Word("-g"), accRoot, syspath.MustAbs("/dev/null"), rootStage.Join(syspath.MustName("ready"))))
}

// v2StartUnits reads the Managed Services V2 projection.
func (a *App) v2StartUnits(ctx context.Context) ([]syspath.Unit, error) {
	if !a.rootTest(ctx, "-f", a.S.V2SystemdState) {
		return nil, nil
	}
	res, err := a.R.RunRoot(ctx, cmdexec.Root(cmdexec.Cat, cmdexec.Word("--"), a.S.V2SystemdState).Stdout(cmdexec.Capture))
	if err != nil || !res.OK() {
		return nil, fail(ExitRefused, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.")
	}
	var doc struct {
		SchemaVersion json.RawMessage `json:"schemaVersion"`
		StartUnits    []string        `json:"startUnits"`
	}
	if json.Unmarshal(res.Stdout, &doc) != nil || string(doc.SchemaVersion) != "1" || doc.StartUnits == nil {
		return nil, fail(ExitRefused, "Refusing to activate secrets: Managed Services V2 runtime state is malformed.")
	}
	units := make([]syspath.Unit, 0, len(doc.StartUnits))
	for _, name := range doc.StartUnits {
		u, err := syspath.NewUnit(name)
		if err != nil {
			return nil, fail(ExitRefused, "Refusing to activate secrets: invalid V2 unit name: %s", name)
		}
		units = append(units, u)
	}
	return units, nil
}

func (a *App) systemctl(ctx context.Context, args ...cmdexec.Arg) bool {
	res, err := a.R.RunRoot(ctx, cmdexec.Root(cmdexec.Systemctl, args...).Stderr(cmdexec.Inherit))
	return err == nil && res.OK()
}

func unitArgs(verb string, flags []string, units ...syspath.Unit) []cmdexec.Arg {
	args := []cmdexec.Arg{cmdexec.Word(verb)}
	for _, f := range flags {
		args = append(args, cmdexec.Word(f))
	}
	for _, u := range units {
		args = append(args, u)
	}
	return args
}

// startServices requires *txn.Swapped: no service is restarted against the
// previous tree.
func (*postSetup) linkUnlockedEnvironment(ctx context.Context, a *App, _ *txn.Swapped) error {
	return a.replaceLink(ctx,
		a.S.SecretRoot.Join(syspath.MustName("authentik")).Join(syspath.MustName("environment")),
		a.S.AuthentikUnlockedEnvironmentFile)
}

func (v *activation) startServices(ctx context.Context, swapped *txn.Swapped, v2 []syspath.Unit) error {
	a := v.a
	if v.post != nil {
		if err := v.post.linkUnlockedEnvironment(ctx, a, swapped); err != nil {
			return err
		}
	}
	if !a.systemctl(ctx, unitArgs("reset-failed", nil, unitPostgres, unitPostgresSetup, unitAuthentikMig, unitAuthentikWorker, unitAuthentik, unitCaddy)...) {
		return fail(ExitFailure, "systemctl reset-failed failed.")
	}
	switch v.mode.(type) {
	case SetupMode:
		ignore := []string{"--job-mode=ignore-dependencies"}
		if !a.systemctl(ctx, unitArgs("start", nil, unitPostgres)...) ||
			!a.systemctl(ctx, unitArgs("start", nil, unitAuthentikMig)...) ||
			!a.systemctl(ctx, unitArgs("start", ignore, unitAuthentik)...) ||
			!a.systemctl(ctx, unitArgs("start", ignore, unitAuthentikWorker)...) ||
			!a.systemctl(ctx, unitArgs("start", ignore, unitCaddy)...) {
			return fail(ExitServiceStart, "Setup identity services failed to start; inspect systemctl --failed.")
		}
	case RuntimeMode:
		if !a.systemctl(ctx, unitArgs("try-restart", nil, unitAuthentikWorker, unitAuthentik)...) {
			return fail(ExitServiceStart, "Authentik failed to restart with the KeePassXC environment; inspect systemctl --failed.")
		}
		if !a.systemctl(ctx, cmdexec.Word("start"), a.S.ProtectedTarget) {
			return fail(ExitServiceStart, "Protected service target failed to start; inspect systemctl --failed.")
		}
		// Target activation does not pull V2-owned units; start only the
		// current projection once the secret gates hold.
		for _, u := range v2 {
			if !a.systemctl(ctx, cmdexec.Word("start"), u) {
				return fail(ExitServiceStart, "Managed Services V2 unit failed to start: %s", u)
			}
		}
	}
	for _, u := range identityUnits {
		if a.rootOK(ctx, cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("is-failed"), cmdexec.Word("--quiet"), u)) {
			return fail(ExitServiceFailed, "Protected service entered the failed state: %s", u)
		}
	}
	if err := a.waitReady(ctx); err != nil {
		return err
	}
	for _, u := range identityUnits {
		if !a.rootOK(ctx, cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("is-active"), cmdexec.Word("--quiet"), u)) {
			return fail(ExitNotActive, "Protected service is not active after readiness validation: %s", u)
		}
	}
	if _, ok := v.mode.(RuntimeMode); ok {
		// Restarting Authentik stops its required outpost; the boot target
		// does not pull it back in during runtime activation.
		if !a.systemctl(ctx, unitArgs("start", nil, unitOutpost)...) {
			return fail(ExitServiceStart, "Authentik proxy outpost failed to restart after activation.")
		}
	}
	return nil
}

// ReadinessWindow bounds the Authentik API readiness probe.
var ReadinessWindow = 90 * time.Second

func (a *App) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(ReadinessWindow)
	probeCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	client := a.HTTP
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
probe:
	for range 91 {
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, a.S.AuthentikReadyURL.String(), nil)
		if err != nil {
			return fail(ExitNotReady, "Authentik readiness probe could not be built.")
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				return nil
			}
		}
		select {
		case <-probeCtx.Done():
			break probe
		case <-time.After(time.Second):
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if a.rootOK(ctx, cmdexec.Root(cmdexec.Systemctl, cmdexec.Word("is-failed"), cmdexec.Word("--quiet"), unitAuthentik)) {
		return fail(ExitServiceFailed, "Authentik failed while waiting for API readiness.")
	}
	if time.Now().After(deadline) {
		return fail(ExitNotReady, "Authentik remained active but did not become API-ready within %d seconds.", int(ReadinessWindow.Seconds()))
	}
	return fail(ExitNotReady, "Authentik readiness probe failed after repeated attempts.")
}

// afterCommit needs Committed evidence. Locked boots need only the
// least-privilege outpost token on disk; the superuser API token now
// resolves through the KeePass tree.
func (v *activation) afterCommit(ctx context.Context, done txn.Committed) error {
	a := v.a
	if v.post == nil {
		return nil
	}
	boot := a.S.BootstrapAuthentikDir
	bootOutpost := boot.Join(syspath.MustName("outpost-token"))
	liveOutpost := done.Root().Join(syspath.MustName("authentik")).Join(syspath.MustName("outpost-token"))
	if v.outpost && a.installOutpost(ctx, liveOutpost, bootOutpost) == nil {
		if err := a.removeFile(ctx, boot.Join(syspath.MustName("api-token"))); err != nil {
			return err
		}
		if err := a.replaceLink(ctx, bootOutpost, a.S.AuthentikRuntimeOutpostTokenFile); err != nil {
			return err
		}
		if err := a.replaceLink(ctx, a.S.AuthentikAPITokenFile, a.S.AuthentikRuntimeAPITokenFile); err != nil {
			return err
		}
	} else {
		a.warn("WARNING: the boot-side Authentik outpost token was not refreshed; browser unlock may be unavailable after reboot.")
	}
	if v.post.retireBootEnvironment {
		return a.removeFile(ctx, boot.Join(syspath.MustName("environment")))
	}
	return nil
}

func (a *App) installOutpost(ctx context.Context, from, to syspath.Abs) error {
	if a.Escalates {
		return a.root(ctx, cmdexec.Root(cmdexec.Install, cmdexec.Word("-m"), cmdexec.Mode(0o400),
			cmdexec.Word("-o"), accRoot, cmdexec.Word("-g"), accRoot, from, to))
	}
	src, err := hostfs.OpenRoot(from.Dir())
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := hostfs.OpenRoot(to.Dir())
	if err != nil {
		return err
	}
	defer dst.Close()
	return secret.InstallPrivateFile(src, from.Base(), dst, to.Base(), 0, 0, true)
}
