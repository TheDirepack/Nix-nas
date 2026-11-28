package nassecrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

func TestDirectLinkAndReadinessRemoval(t *testing.T) {
	dir := t.TempDir()
	target := syspath.MustAbs(filepath.Join(dir, "environment"))
	link := syspath.MustAbs(filepath.Join(dir, "unlocked-environment"))
	if err := os.WriteFile(target.String(), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	a := App{}
	ctx := context.Background()
	if err := a.replaceLink(ctx, target, link); err != nil {
		t.Fatal(err)
	}
	if !a.rootTest(ctx, "-L", link) || !a.rootTest(ctx, "-f", link) || !a.rootTest(ctx, "-e", target) {
		t.Fatal("unexpected link or status probe")
	}
	if err := a.removeFile(ctx, link); err != nil {
		t.Fatal(err)
	}
	if !a.rootTest(ctx, "-f", target) || a.rootTest(ctx, "-e", link) {
		t.Fatal("unlink did not preserve the target")
	}
}

func TestDirectOutpostInstallRefusesAnUnavailableDestination(t *testing.T) {
	dir := t.TempDir()
	source := syspath.MustAbs(filepath.Join(dir, "outpost-token"))
	dest := syspath.MustAbs(filepath.Join(dir, "missing", "outpost-token"))
	if err := os.WriteFile(source.String(), []byte("fixture"), 0o400); err != nil {
		t.Fatal(err)
	}
	a := App{}
	if err := a.installOutpost(context.Background(), source, dest); !os.IsNotExist(err) {
		t.Fatalf("missing destination parent: %v", err)
	}
	if data, err := os.ReadFile(source.String()); err != nil || string(data) != "fixture" {
		t.Fatal("a failed token install changed the source")
	}
}
