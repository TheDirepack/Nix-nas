package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"golang.org/x/text/cases"
)

// MaxLineRunes bounds every secret line this appliance reads.
const MaxLineRunes = 4096

// LineError classifies a rejected secret line. The variants are exhaustive.
type LineError int

const (
	// LineMissing means input ended before a newline-terminated line.
	LineMissing LineError = iota
	// LineTooLong means the line exceeded MaxLineRunes.
	LineTooLong
	// LineEmpty means the line held no characters.
	LineEmpty
	// LineMalformed means NUL or invalid UTF-8.
	LineMalformed
)

func (e LineError) Error() string {
	switch e {
	case LineMissing:
		return "secret line is missing"
	case LineTooLong:
		return fmt.Sprintf("secret line exceeds %d characters", MaxLineRunes)
	case LineEmpty:
		return "secret line is empty"
	case LineMalformed:
		return "secret line is malformed"
	}
	return "secret line is invalid"
}

// ReadLine reads one newline-terminated line of at most maxRunes UTF-8
// characters. It never buffers past the newline, so later reads on r see the
// following line. The newline is not part of the secret.
func ReadLine(r io.ByteReader, maxRunes int) (Secret, error) {
	buf := make([]byte, 0, 64)
	fail := func(err error) (Secret, error) {
		clear(buf)
		return Secret{}, err
	}
	runes := 0
	for {
		c, err := r.ReadByte()
		if err != nil {
			return fail(LineMissing)
		}
		if c == '\n' {
			break
		}
		if c == 0 {
			return fail(LineMalformed)
		}
		if len(buf) == maxRunes*utf8.UTFMax {
			return fail(LineTooLong)
		}
		if c&0xC0 != 0x80 {
			runes++
			if runes > maxRunes {
				return fail(LineTooLong)
			}
		}
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), 2*cap(buf))
			copy(grown, buf)
			clear(buf)
			buf = grown
		}
		buf = append(buf, c)
	}
	if !utf8.Valid(buf) {
		return fail(LineMalformed)
	}
	if len(buf) == 0 {
		return fail(LineEmpty)
	}
	return FromBytes(buf), nil
}

// RuneCount is the number of UTF-8 characters, the unit Python's len() uses.
func (s Secret) RuneCount() int { return utf8.RuneCount(s.bytes()) }

// HasControl reports C0 control characters or DEL.
func (s Secret) HasControl() bool {
	for _, c := range s.bytes() {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// KeePassPassword is a nonempty, bounded, single-line database password.
type KeePassPassword struct{ s Secret }

// ErrPasswordEmpty and ErrPasswordTooLong are the KeePass password bounds.
var (
	ErrPasswordEmpty   = errors.New("The KeePass database password cannot be empty.")
	ErrPasswordTooLong = fmt.Errorf("The KeePass database password exceeds %d characters.", MaxLineRunes)
)

// NewKeePassPassword applies the shared bounds.
func NewKeePassPassword(s Secret) (KeePassPassword, error) {
	switch {
	case s.Empty():
		return KeePassPassword{}, ErrPasswordEmpty
	case s.RuneCount() > MaxLineRunes:
		return KeePassPassword{}, ErrPasswordTooLong
	case s.indexByte('\n') >= 0 || s.indexByte(0) >= 0:
		return KeePassPassword{}, LineMalformed
	case !utf8.Valid(s.bytes()):
		return KeePassPassword{}, LineMalformed
	}
	return KeePassPassword{s: s}, nil
}

func (p KeePassPassword) secret() Secret { return p.s }

// Destroy zeroises the password.
func (p KeePassPassword) Destroy() { p.s.Destroy() }

// Strength floor for a KeePass database password that is created by setup.
const (
	KeePassMinLength   = 16
	KeePassMinDistinct = 6
)

// StrengthError is a rejected strength rule; the variants are exhaustive.
type StrengthError int

const (
	// TooShort is fewer than KeePassMinLength characters.
	TooShort StrengthError = iota
	// TooFewDistinct is fewer than KeePassMinDistinct different characters.
	TooFewDistinct
	// SameAsAdministrator matches the administrator password case-insensitively.
	SameAsAdministrator
)

func (e StrengthError) Error() string {
	switch e {
	case TooShort:
		return fmt.Sprintf("KeePass database password must contain at least %d characters", KeePassMinLength)
	case TooFewDistinct:
		return fmt.Sprintf("KeePass database password must use at least %d different characters", KeePassMinDistinct)
	case SameAsAdministrator:
		return "KeePass database password must differ from the administrator password"
	}
	return "KeePass database password is too weak"
}

// StrongKeePassPassword can only be obtained from NewStrongKeePassPassword.
type StrongKeePassPassword struct{ p KeePassPassword }

// NewStrongKeePassPassword enforces the setup strength floor. administrator
// may be nil when no administrator password is being set.
func NewStrongKeePassPassword(p KeePassPassword, administrator *Secret) (StrongKeePassPassword, error) {
	b := p.s.bytes()
	if utf8.RuneCount(b) < KeePassMinLength {
		return StrongKeePassPassword{}, TooShort
	}
	distinct := map[rune]struct{}{}
	for _, r := range string(b) { // #nosec -- ranging converts without retaining a string copy beyond the loop
		distinct[r] = struct{}{}
	}
	if len(distinct) < KeePassMinDistinct {
		return StrongKeePassPassword{}, TooFewDistinct
	}
	if administrator != nil && foldEqual(b, administrator.bytes()) {
		return StrongKeePassPassword{}, SameAsAdministrator
	}
	return StrongKeePassPassword{p: p}, nil
}

// Password widens to the plain password type.
func (s StrongKeePassPassword) Password() KeePassPassword { return s.p }

func (s StrongKeePassPassword) secret() Secret { return s.p.s }

// foldEqual is full Unicode case folding, matching Python's str.casefold.
func foldEqual(a, b []byte) bool {
	fa := cases.Fold().Bytes(a)
	fb := cases.Fold().Bytes(b)
	defer clear(fa)
	defer clear(fb)
	return subtle.ConstantTimeCompare(fa, fb) == 1
}
