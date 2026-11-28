// Command nas-keepass-setup is the KeePass half of first-start setup. Every
// secret arrives on stdin, one line each; argv carries only paths, account
// names and modes.
//
//	check-strength       stdin: keepass, [administrator]
//	verifier create      stdin: keepass, N, then N (username, password) pairs
//	verifier verify      stdin: verifier JSON, keepass, N, pairs   (exit 3: mismatch)
//	verifier legacy      stdin: keepass, N, pairs
//	database --mode create|verify --database P [--key-file K] --owner U
//	         --managed-dataset encrypted|unencrypted|unknown
//	                     stdin: keepass, [administrator]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/lineio"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/setupkp"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

const (
	exitOK       = 0
	exitFailure  = 1
	exitUsage    = 2
	exitMismatch = 3
)

const usage = "usage: nas-keepass-setup {check-strength|verifier create|verifier verify|verifier legacy|database ...}"

func main() { os.Exit(run(os.Args[1:])) }

func die(code int, err error) int {
	fmt.Fprintln(os.Stderr, err)
	return code
}

func run(args []string) int {
	if len(args) == 0 {
		return die(exitUsage, errors.New(usage))
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(os.Stdout, usage)
		return exitOK
	}
	in := lineio.NewStdin(os.Stdin)
	switch args[0] {
	case "check-strength":
		if len(args) != 1 {
			return die(exitUsage, errors.New("check-strength takes no arguments"))
		}
		return checkStrength(in)
	case "verifier":
		if len(args) != 2 {
			return die(exitUsage, errors.New("usage: nas-keepass-setup verifier {create|verify|legacy}"))
		}
		return verifier(in, args[1])
	case "database":
		return database(in, args[1:])
	}
	return die(exitUsage, errors.New(usage))
}

func readPassword(in *lineio.Stdin) (secret.KeePassPassword, error) {
	raw, err := in.Line()
	if err != nil {
		return secret.KeePassPassword{}, errors.New("KeePass database password must contain exactly one non-empty line without control characters")
	}
	if raw.HasControl() {
		raw.Destroy()
		return secret.KeePassPassword{}, errors.New("KeePass database password must contain exactly one non-empty line without control characters")
	}
	return secret.NewKeePassPassword(raw)
}

// readOptionalAdmin reads an administrator line when one follows.
func readOptionalAdmin(in *lineio.Stdin) (*secret.Secret, error) {
	raw, err := in.Line()
	switch {
	case errors.Is(err, secret.LineMissing):
		return nil, nil
	case err != nil:
		return nil, errors.New("administrator password line is malformed")
	}
	if err := in.ExpectEOF(); err != nil {
		raw.Destroy()
		return nil, err
	}
	return &raw, nil
}

func checkStrength(in *lineio.Stdin) int {
	pw, err := readPassword(in)
	if err != nil {
		return die(exitFailure, err)
	}
	defer pw.Destroy()
	admin, err := readOptionalAdmin(in)
	if err != nil {
		return die(exitFailure, err)
	}
	if admin != nil {
		defer admin.Destroy()
	}
	if _, err := secret.NewStrongKeePassPassword(pw, admin); err != nil {
		return die(exitFailure, err)
	}
	return exitOK
}

func readAccounts(in *lineio.Stdin) ([]secret.AccountPassword, error) {
	countLine, err := in.PlainLine()
	if err != nil {
		return nil, errors.New("account count is missing")
	}
	n, err := strconv.Atoi(countLine)
	if err != nil || n < 0 || n > 1024 {
		return nil, errors.New("account count is invalid")
	}
	out := make([]secret.AccountPassword, 0, n)
	for range n {
		user, err := in.PlainLine()
		if err != nil {
			return nil, errors.New("account username line is malformed")
		}
		pw, err := in.Line()
		if err != nil {
			return nil, errors.New("account password line is malformed")
		}
		out = append(out, secret.AccountPassword{Username: user, Password: pw})
	}
	if err := in.ExpectEOF(); err != nil {
		return nil, err
	}
	return out, nil
}

func destroyAccounts(accounts []secret.AccountPassword) {
	for _, a := range accounts {
		a.Password.Destroy()
	}
}

func verifier(in *lineio.Stdin, action string) int {
	var stored setupkp.StoredVerifier
	if action == "verify" {
		line, err := in.PlainLine()
		if err != nil {
			return die(exitFailure, errors.New("verifier line is malformed"))
		}
		if json.Unmarshal([]byte(line), &stored) != nil {
			return exitMismatch
		}
	} else if action != "create" && action != "legacy" {
		return die(exitUsage, fmt.Errorf("unknown verifier action %q", action))
	}
	pw, err := readPassword(in)
	if err != nil {
		return die(exitFailure, err)
	}
	defer pw.Destroy()
	accounts, err := readAccounts(in)
	if err != nil {
		return die(exitFailure, err)
	}
	defer destroyAccounts(accounts)
	enc := json.NewEncoder(os.Stdout)
	switch action {
	case "create":
		v, err := secret.NewVerifier(pw, accounts)
		if err != nil {
			return die(exitFailure, err)
		}
		_ = enc.Encode(v)
	case "verify":
		ok, err := stored.Verifier().Matches(pw, accounts)
		if err != nil {
			return die(exitFailure, err)
		}
		if !ok {
			return exitMismatch
		}
	case "legacy":
		_ = enc.Encode(secret.LegacyAuthenticators(pw, accounts))
	}
	return exitOK
}

func database(in *lineio.Stdin, args []string) int {
	fs := flag.NewFlagSet("database", flag.ContinueOnError)
	modeFlag := fs.String("mode", "", "create or verify")
	dbFlag := fs.String("database", "", "KDBX path")
	keyFlag := fs.String("key-file", "", "optional key file")
	ownerFlag := fs.String("owner", "", "database owner")
	datasetFlag := fs.String("managed-dataset", "unknown", "encrypted, unencrypted or unknown")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exitUsage
	}
	var mode setupkp.Mode
	switch *modeFlag {
	case "create":
		mode = setupkp.Create
	case "verify":
		mode = setupkp.VerifyOnly
	default:
		return die(exitUsage, errors.New("--mode must be create or verify"))
	}
	dataset := setupkp.DatasetUnknown
	switch *datasetFlag {
	case "encrypted":
		dataset = setupkp.DatasetEncrypted
	case "unencrypted":
		dataset = setupkp.DatasetUnencrypted
	case "unknown":
	default:
		return die(exitUsage, errors.New("--managed-dataset must be encrypted, unencrypted or unknown"))
	}
	path, err := syspath.NewAbs(*dbFlag)
	if err != nil {
		return die(exitUsage, err)
	}
	owner, err := syspath.NewAccount(*ownerFlag)
	if err != nil {
		return die(exitUsage, err)
	}
	var key *syspath.Abs
	if *keyFlag != "" {
		k, err := syspath.NewAbs(*keyFlag)
		if err != nil {
			return die(exitUsage, err)
		}
		key = &k
	}
	pw, err := readPassword(in)
	if err != nil {
		return die(exitFailure, err)
	}
	defer pw.Destroy()
	admin, err := readOptionalAdmin(in)
	if err != nil {
		return die(exitFailure, err)
	}
	if admin != nil {
		defer admin.Destroy()
	}
	runner := cmdexec.NewOS()
	runner.NonInteractive = true
	db := &setupkp.Database{Path: path, KeyFile: key, Owner: owner, Runner: runner, Escalate: runner.Escalate, Progress: os.Stderr}
	res, err := db.VerifyOrCreate(context.Background(), mode, pw, admin, dataset)
	if err != nil {
		return die(exitFailure, err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(res)
	return exitOK
}
