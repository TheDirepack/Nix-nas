package txn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

func TestDirectFSRejectsAnOccupiedDestination(t *testing.T) {
	d := t.TempDir()
	src := syspath.MustAbs(filepath.Join(d, "src"))
	dst := syspath.MustAbs(filepath.Join(d, "dst"))
	for _, p := range []syspath.Abs{src, dst} {
		if err := os.Mkdir(p.String(), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ready := src.Join(syspath.MustName("ready"))
	if err := os.WriteFile(ready.String(), nil, 0o400); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fs := DirectFS{}
	if !fs.IsDir(ctx, src) || !fs.IsFile(ctx, ready) || fs.IsSymlink(ctx, src) || !fs.Exists(ctx, dst) {
		t.Fatal("unexpected filesystem observation")
	}
	if real, err := fs.Realpath(ctx, src); err != nil || real != src.String() {
		t.Fatalf("directory validation: %q %v", real, err)
	}
	if err := fs.Move(ctx, src, dst); !errors.Is(err, unix.EEXIST) || !fs.Exists(ctx, ready) {
		t.Fatalf("occupied destination: %v", err)
	}
	if err := fs.RemoveAll(ctx, dst); err != nil {
		t.Fatal(err)
	}
	if err := fs.Move(ctx, src, dst); err != nil {
		t.Fatal(err)
	}
}
