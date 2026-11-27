// Package lineio reads secret lines from stdin without userspace buffering,
// so no copy of a secret survives in a bufio buffer and child processes
// never inherit unread payload bytes.
package lineio

import (
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/TheDirepack/Nix-nas/go/internal/secret"
)

// Stdin reads one byte per system call.
type Stdin struct {
	f   *os.File
	one [1]byte
}

// NewStdin wraps f, normally os.Stdin.
func NewStdin(f *os.File) *Stdin { return &Stdin{f: f} }

// ReadByte implements io.ByteReader.
func (s *Stdin) ReadByte() (byte, error) {
	for {
		n, err := s.f.Read(s.one[:])
		if n == 1 {
			c := s.one[0]
			s.one[0] = 0
			return c, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// Line reads one bounded secret line.
func (s *Stdin) Line() (secret.Secret, error) { return secret.ReadLine(s, secret.MaxLineRunes) }

// ErrExtraInput means bytes followed the expected lines.
var ErrExtraInput = errors.New("unexpected extra input")

// ExpectEOF rejects any further byte on stdin.
func (s *Stdin) ExpectEOF() error {
	_, err := s.ReadByte()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrExtraInput
}

// IsTerminal reports whether stdin is a terminal.
func (s *Stdin) IsTerminal() bool {
	_, err := unix.IoctlGetTermios(int(s.f.Fd()), unix.TCGETS) // #nosec -- fd fits int
	return err == nil
}

// Prompt writes prompt to stderr and reads a line with echo disabled when
// stdin is a terminal. The trailing newline goes to stderr so stdout stays
// clean for commands whose output is a secret.
func (s *Stdin) Prompt(prompt string) (secret.Secret, error) {
	fd := int(s.f.Fd()) // #nosec -- fd fits int
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	switch {
	case err == nil:
		quiet := *old
		quiet.Lflag &^= unix.ECHO
		if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
			return secret.Secret{}, err
		}
		defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }()
	case !errors.Is(err, unix.ENOTTY):
		return secret.Secret{}, err
	}
	_, _ = io.WriteString(os.Stderr, prompt)
	line, err := s.Line()
	_, _ = io.WriteString(os.Stderr, "\n")
	return line, err
}

// ErrPlainLine rejects a non-secret line with control characters, invalid
// UTF-8 or no terminating newline.
var ErrPlainLine = errors.New("malformed input line")

// PlainLine reads one bounded non-secret line such as a username.
func (s *Stdin) PlainLine() (string, error) {
	var out []byte
	for len(out) <= 256 {
		c, err := s.ReadByte()
		if err != nil {
			return "", ErrPlainLine
		}
		if c == '\n' {
			if len(out) == 0 || !utf8.Valid(out) {
				return "", ErrPlainLine
			}
			return string(out), nil
		}
		if c < 0x20 || c == 0x7f {
			return "", ErrPlainLine
		}
		out = append(out, c)
	}
	return "", ErrPlainLine
}
