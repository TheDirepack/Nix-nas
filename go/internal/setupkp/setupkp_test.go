package setupkp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

type prepareOnlyRunner struct {
	cmdexec.Runner
	t *testing.T
}

func (r prepareOnlyRunner) Run(_ context.Context, c cmdexec.Command) (cmdexec.Result, error) {
	r.t.Helper()
	if c.Argv()[0] != "sudo" {
		r.t.Fatalf("unexpected command %q", c.Argv()[0])
	}
	return cmdexec.Result{}, nil
}

func (r prepareOnlyRunner) RunRoot(_ context.Context, c cmdexec.Privileged) (cmdexec.Result, error) {
	r.t.Helper()
	if c.Argv()[0] != "install" {
		r.t.Fatalf("unexpected privileged command %q", c.Argv()[0])
	}
	return cmdexec.Result{}, nil
}

func TestMoveAsideCollisionKeepsBothDatabases(t *testing.T) {
	dir := t.TempDir()
	path := syspath.MustAbs(filepath.Join(dir, "NAS.kdbx"))
	timeOfCollision := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	aside := path.String() + ".replaced-20260101T000000Z"
	for p, content := range map[string]string{path.String(): "original", aside: "previous copy"} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	db := Database{
		Path: path, Owner: usersGroup, Runner: prepareOnlyRunner{t: t}, Escalate: true,
		Now: func() time.Time { return timeOfCollision },
	}
	pw, err := secret.NewKeePassPassword(secret.FromBytes([]byte("example fixture password")))
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Destroy()
	_, err = db.VerifyOrCreate(context.Background(), Create, pw, nil, DatasetUnencrypted)
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("collision: %v", err)
	}
	for p, want := range map[string]string{path.String(): "original", aside: "previous copy"} {
		data, err := os.ReadFile(p)
		if err != nil || string(data) != want {
			t.Fatalf("database %s changed: %v", p, err)
		}
	}
}
