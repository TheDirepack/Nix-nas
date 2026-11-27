// Package syspath holds validated, non-secret identifiers that may appear in
// argv: absolute paths, path components, systemd unit names and account
// names. Each type has unexported fields and a smart constructor.
package syspath

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Abs is a lexically clean absolute path without NUL or newline.
type Abs struct{ p string }

// ErrNotAbsolute and friends classify rejected paths.
var (
	ErrNotAbsolute = errors.New("path must be absolute")
	ErrUnsafePath  = errors.New("path contains NUL or a line break")
	ErrDotDot      = errors.New("path must not contain .. components")
)

// NewAbs canonicalizes dot and dot-dot lexically, without following symlinks.
func NewAbs(s string) (Abs, error) {
	if !strings.HasPrefix(s, "/") {
		return Abs{}, fmt.Errorf("%w: %q", ErrNotAbsolute, s)
	}
	if strings.ContainsAny(s, "\x00\n\r") {
		return Abs{}, ErrUnsafePath
	}
	return Abs{p: path.Clean(s)}, nil
}

// MustAbs is for compile-time constant paths only.
func MustAbs(s string) Abs {
	a, err := NewAbs(s)
	if err != nil {
		panic(err)
	}
	return a
}

// NewAbsNoDotDot additionally rejects any ".." component before cleaning,
// the socket-path rule of nas-unlock-api.
func NewAbsNoDotDot(s string) (Abs, error) {
	for _, part := range strings.Split(s, "/") {
		if part == ".." {
			return Abs{}, ErrDotDot
		}
	}
	return NewAbs(s)
}

func (a Abs) String() string    { return a.p }
func (a Abs) ArgString() string { return a.p }

// IsZero reports the zero value, which no constructor returns.
func (a Abs) IsZero() bool { return a.p == "" }

// IsRoot reports "/".
func (a Abs) IsRoot() bool { return a.p == "/" }

// Dir is the lexical parent.
func (a Abs) Dir() Abs { return Abs{p: path.Dir(a.p)} }

// Base is the final component.
func (a Abs) Base() string { return path.Base(a.p) }

// Join appends one validated component.
func (a Abs) Join(n Name) Abs { return Abs{p: path.Join(a.p, n.s)} }

// Overlaps reports equality or ancestry in either direction.
func (a Abs) Overlaps(b Abs) bool {
	return a.p == b.p || strings.HasPrefix(a.p, b.p+"/") || strings.HasPrefix(b.p, a.p+"/") ||
		a.p == "/" || b.p == "/"
}

// Name is a single path component.
type Name struct{ s string }

// NewName rejects separators, dot entries and control characters.
func NewName(s string) (Name, error) {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\x00\n\r") {
		return Name{}, fmt.Errorf("invalid path component %q", s)
	}
	return Name{s: s}, nil
}

// MustName is for compile-time constant names only.
func MustName(s string) Name {
	n, err := NewName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func (n Name) String() string { return n.s }

var unitPattern = regexp.MustCompile(`^[A-Za-z0-9_.@:-]+\.(service|socket|timer|path|target|mount)$`)

// Unit is a systemd unit name that cannot be mistaken for an option.
type Unit struct{ s string }

// NewUnit validates the unit-name alphabet and suffix.
func NewUnit(s string) (Unit, error) {
	if !unitPattern.MatchString(s) || strings.HasPrefix(s, "-") {
		return Unit{}, fmt.Errorf("invalid systemd unit name: %q", s)
	}
	return Unit{s: s}, nil
}

// MustUnit is for compile-time constant names only.
func MustUnit(s string) Unit {
	u, err := NewUnit(s)
	if err != nil {
		panic(err)
	}
	return u
}

func (u Unit) String() string    { return u.s }
func (u Unit) ArgString() string { return u.s }

// Target is a Unit whose suffix is .target.
type Target struct{ u Unit }

// NewTarget validates a .target unit.
func NewTarget(s string) (Target, error) {
	u, err := NewUnit(s)
	if err != nil || !strings.HasSuffix(s, ".target") {
		return Target{}, fmt.Errorf("invalid protected target name: %q", s)
	}
	return Target{u: u}, nil
}

func (t Target) String() string    { return t.u.s }
func (t Target) ArgString() string { return t.u.s }

// Unit widens a target.
func (t Target) Unit() Unit { return t.u }

var accountPattern = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// Account is a POSIX user or group name.
type Account struct{ s string }

// NewAccount validates a conservative POSIX name.
func NewAccount(s string) (Account, error) {
	if !accountPattern.MatchString(s) {
		return Account{}, fmt.Errorf("invalid account name: %q", s)
	}
	return Account{s: s}, nil
}

// MustAccount is for compile-time constant names only.
func MustAccount(s string) Account {
	a, err := NewAccount(s)
	if err != nil {
		panic(err)
	}
	return a
}

func (a Account) String() string    { return a.s }
func (a Account) ArgString() string { return a.s }
