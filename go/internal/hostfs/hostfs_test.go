package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

func TestMoveRefusesExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := syspath.MustAbs(filepath.Join(dir, "src"))
	dst := syspath.MustAbs(filepath.Join(dir, "dst"))
	if err := os.WriteFile(src.String(), []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing", dst.String()); err != nil {
		t.Fatal(err)
	}
	if err := MoveDatabase(src, dst, nil); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("destination collision: %v", err)
	}
	if err := Unlink(dst); err != nil {
		t.Fatal(err)
	}
	if err := MoveDatabase(src, dst, nil); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst.String())
	if err != nil || string(got) != "original" {
		t.Fatalf("saved database: %q, %v", got, err)
	}
	if _, err := Lstat(src); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("source still exists: %v", err)
	}
}

func TestMoveDoesNotTraverseSymlinkedParent(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	src := syspath.MustAbs(filepath.Join(dir, "src"))
	dst := syspath.MustAbs(filepath.Join(dir, "link", "dst"))
	if err := os.Mkdir(src.String(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := MoveNoReplace(src, dst); err == nil {
		t.Fatal("moved through a symlink")
	}
	if err := RemoveAll(dst); err == nil {
		t.Fatal("removed through a symlink")
	}
	if err := RemoveAll(dst.Dir()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("unlink followed the symlink:", err)
	}
	if err := MoveNoReplace(src, syspath.MustAbs(filepath.Join(dir, "next"))); err != nil {
		t.Fatal(err)
	}
}

func TestLinkFallbackPreservesAnExistingDestination(t *testing.T) {
	dir := syspath.MustAbs(t.TempDir())
	for _, name := range []string{"from", "to"} {
		if err := os.WriteFile(filepath.Join(dir.String(), name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := openDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := linkThenUnlink(fd, "from", fd, "to"); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("collision: %v", err)
	}
	if err := linkThenUnlink(fd, "from", fd, "preserved"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir.String(), "preserved")); err != nil || string(data) != "from" {
		t.Fatalf("preserved data: %q %v", data, err)
	}
}

func TestRootFileOperationsUseTheNamedEntry(t *testing.T) {
	dir := syspath.MustAbs(t.TempDir()).Join(syspath.MustName("new"))
	if err := Mkdir(dir, os.Getuid(), os.Getgid(), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("file", []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	file := dir.Join(syspath.MustName("file"))
	if err := RestoreFileMetadata(file, os.Getuid(), os.Getgid(), 0o400); err != nil {
		t.Fatal(err)
	}
	link := dir.Join(syspath.MustName("link"))
	if err := ReplaceSymlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := RestoreFileMetadata(link, os.Getuid(), os.Getgid(), 0o600); !errors.Is(err, unix.ELOOP) {
		t.Fatalf("metadata operation followed a symlink: %v", err)
	}
	st, err := Lstat(file)
	if err != nil || st.Mode&0o777 != 0o400 {
		t.Fatalf("file mode %o: %v", st.Mode, err)
	}
	if err := Unlink(link); err != nil {
		t.Fatal(err)
	}
	if err := RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
}
