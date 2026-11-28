// Package hostfs provides descriptor-relative operations for appliance paths.
package hostfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

const directoryFlags = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

// openDir traverses each path component without following symlinks.
func openDir(p syspath.Abs, create bool) (int, error) {
	if p.IsZero() {
		return -1, syspath.ErrNotAbsolute
	}
	fd, err := unix.Open("/", directoryFlags, 0)
	if err != nil {
		return -1, err
	}
	parts := strings.Split(strings.TrimPrefix(p.String(), "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		child, err := unix.Openat(fd, part, directoryFlags, 0)
		if create && errors.Is(err, unix.ENOENT) {
			mode := uint32(0o755)
			if i == len(parts)-1 {
				mode = 0o700
			}
			err = unix.Mkdirat(fd, part, mode)
			if err == nil || errors.Is(err, unix.EEXIST) {
				child, err = unix.Openat(fd, part, directoryFlags, 0)
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			return -1, &os.PathError{Op: "open directory", Path: p.String(), Err: err}
		}
		fd = child
	}
	return fd, nil
}

func openParent(p syspath.Abs) (int, error) {
	if p.IsZero() || p.IsRoot() {
		return -1, unix.EINVAL
	}
	return openDir(p.Dir(), false)
}

func CheckDir(p syspath.Abs) error {
	fd, err := openDir(p, false)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

func Mkdir(p syspath.Abs, uid, gid int, mode uint32) error {
	if p.IsZero() || p.IsRoot() {
		return unix.EINVAL
	}
	fd, err := openDir(p, true)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	dir, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := unix.Fchown(dir, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(dir, mode)
}

func Lstat(p syspath.Abs) (unix.Stat_t, error) {
	var st unix.Stat_t
	fd, err := openParent(p)
	if err != nil {
		return st, err
	}
	defer unix.Close(fd)
	err = unix.Fstatat(fd, p.Base(), &st, unix.AT_SYMLINK_NOFOLLOW)
	return st, err
}

func RemoveAll(p syspath.Abs) error {
	fd, err := openParent(p)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// os.Root owns a descriptor to the same directory during recursive removal.
	root, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return err
	}
	defer root.Close()
	return root.RemoveAll(p.Base())
}

// MoveNoReplace atomically moves a transaction entry into an empty name.
func MoveNoReplace(src, dst syspath.Abs) error { return move(src, dst, nil) }

// MoveDatabase may fall back to preserving a regular file by hard link on
// filesystems without RENAME_NOREPLACE. The setup coordinator owns serialization.
func MoveDatabase(src, dst syspath.Abs, diagnostics io.Writer) error {
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	return move(src, dst, diagnostics)
}

func move(src, dst syspath.Abs, diagnostics io.Writer) error {
	from, err := openParent(src)
	if err != nil {
		return err
	}
	defer unix.Close(from)
	to := from
	if src.Dir() != dst.Dir() {
		to, err = openParent(dst)
		if err != nil {
			return err
		}
		defer unix.Close(to)
	}
	oldName, newName := src.Base(), dst.Base()
	if diagnostics != nil {
		var st unix.Stat_t
		if err := unix.Fstatat(from, oldName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return unix.EINVAL
		}
	}
	err = unix.Renameat2(from, oldName, to, newName, unix.RENAME_NOREPLACE)
	if diagnostics == nil || !(errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS)) {
		return err
	}
	fmt.Fprintln(diagnostics, "nas-setup: atomic rename unavailable; preserving the previous database by hard link.")
	return linkThenUnlink(from, oldName, to, newName)
}

func linkThenUnlink(from int, oldName string, to int, newName string) error {
	var before, after, saved unix.Stat_t
	if err := unix.Fstatat(from, oldName, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.EINVAL
	}
	if err := unix.Linkat(from, oldName, to, newName, 0); err != nil {
		return err
	}
	if err := unix.Fstatat(from, oldName, &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if err := unix.Fstatat(to, newName, &saved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if before.Ino != after.Ino || before.Dev != after.Dev || before.Ino != saved.Ino || before.Dev != saved.Dev {
		return errors.New("database changed during move-aside; inspect both names")
	}
	return unix.Unlinkat(from, oldName, 0)
}

func OpenRoot(p syspath.Abs) (*os.Root, error) {
	fd, err := openDir(p, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
}

func Unlink(p syspath.Abs) error {
	fd, err := openParent(p)
	if err == nil {
		defer unix.Close(fd)
		err = unix.Unlinkat(fd, p.Base(), 0)
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func ReplaceSymlink(target, path syspath.Abs) error {
	fd, err := openParent(path)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	tmp := ".link-" + rand.Text()
	if err := unix.Symlinkat(target.String(), fd, tmp); err != nil {
		return err
	}
	defer unix.Unlinkat(fd, tmp, 0)
	return unix.Renameat(fd, tmp, fd, path.Base())
}

func RestoreFileMetadata(p syspath.Abs, uid, gid int, mode uint32) error {
	parent, err := openParent(p)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, p.Base(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return unix.EINVAL
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, mode)
}

func UserID(name syspath.Account) (int, error) {
	if name.String() == "root" {
		return 0, nil
	}
	u, err := user.Lookup(name.String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(u.Uid)
}

func GroupID(name syspath.Account) (int, error) {
	if name.String() == "root" {
		return 0, nil
	}
	g, err := user.LookupGroup(name.String())
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(g.Gid)
}
