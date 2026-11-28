package secret

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// FormatError reports a KeePass value with an unsafe or unexpected format.
// The label is non-secret; the value never appears in the message.
type FormatError struct{ Label string }

func (e *FormatError) Error() string {
	return e.Label + " has an unsafe or unexpected format in KeePassXC."
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func isAlnum(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// atomByte is the environment-file-safe alphabet [A-Za-z0-9._~+/=:@-].
func atomByte(c byte) bool {
	switch c {
	case '.', '_', '~', '+', '/', '=', ':', '@', '-':
		return true
	}
	return isAlnum(c)
}

// tokenByte is the Authentik token alphabet [A-Za-z0-9._~-].
func tokenByte(c byte) bool {
	switch c {
	case '.', '_', '~', '-':
		return true
	}
	return isAlnum(c)
}

// topicByte is the ntfy topic alphabet [A-Za-z0-9_-].
func topicByte(c byte) bool { return c == '_' || c == '-' || isAlnum(c) }

func all(b []byte, ok func(byte) bool) bool {
	for _, c := range b {
		if !ok(c) {
			return false
		}
	}
	return true
}

// HexKey is a secret of exactly a configured number of hex digits.
type HexKey struct{ s Secret }

// NewHexKey validates s as exactly digits hex characters.
func NewHexKey(s Secret, digits int, label string) (HexKey, error) {
	b := s.bytes()
	if len(b) != digits || !all(b, isHex) {
		return HexKey{}, &FormatError{Label: label}
	}
	return HexKey{s: s}, nil
}

// RandomHex returns n random bytes hex-encoded, like `openssl rand -hex n`.
func RandomHex(n int) (HexKey, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return HexKey{}, fmt.Errorf("secret: random source: %w", err)
	}
	out := make([]byte, hex.EncodedLen(n))
	hex.Encode(out, raw)
	clear(raw)
	return HexKey{s: FromBytes(out)}, nil
}

func (k HexKey) appendTo(dst []byte) []byte { return k.s.appendRaw(dst) }
func (k HexKey) secret() Secret             { return k.s }

// Secret returns the underlying opaque secret.
func (k HexKey) Secret() Secret { return k.s }

// Atom is a secret restricted to the environment-file-safe alphabet.
type Atom struct{ s Secret }

// NewAtom validates length bounds and the atom alphabet.
func NewAtom(s Secret, label string, minimum, maximum int) (Atom, error) {
	b := s.bytes()
	if len(b) < minimum || len(b) > maximum || len(b) == 0 || !all(b, atomByte) {
		return Atom{}, &FormatError{Label: label}
	}
	return Atom{s: s}, nil
}

func (a Atom) appendTo(dst []byte) []byte { return a.s.appendRaw(dst) }
func (a Atom) secret() Secret             { return a.s }

// Secret returns the underlying opaque secret.
func (a Atom) Secret() Secret { return a.s }

// AtomFromHex widens a validated hex key; hex is a subset of the atom alphabet.
func AtomFromHex(k HexKey) Atom { return Atom(k) }

// APIToken is an Authentik API or outpost token: [A-Za-z0-9._~-]{20,4096}.
type APIToken struct{ s Secret }

// TokenFormatError is the operator-facing token rejection.
type TokenFormatError struct{ Label string }

func (e *TokenFormatError) Error() string { return e.Label + " format is invalid." }

// NewAPIToken validates the Authentik token alphabet and length.
func NewAPIToken(s Secret, label string) (APIToken, error) {
	b := s.bytes()
	if len(b) < 20 || len(b) > 4096 || !all(b, tokenByte) {
		return APIToken{}, &TokenFormatError{Label: label}
	}
	return APIToken{s: s}, nil
}

func (t APIToken) appendTo(dst []byte) []byte { return t.s.appendRaw(dst) }
func (t APIToken) secret() Secret             { return t.s }

// Secret returns the underlying opaque secret.
func (t APIToken) Secret() Secret { return t.s }

// NtfyTopic is the private alert topic: [A-Za-z0-9_-]{8,128}.
type NtfyTopic struct{ s Secret }

// NewNtfyTopic validates the topic alphabet, which also keeps it out of URL
// path traversal and curl config injection.
func NewNtfyTopic(s Secret) (NtfyTopic, error) {
	b := s.bytes()
	if len(b) < 8 || len(b) > 128 || !all(b, topicByte) {
		return NtfyTopic{}, &FormatError{Label: "ntfy alert topic"}
	}
	return NtfyTopic{s: s}, nil
}

func (t NtfyTopic) appendTo(dst []byte) []byte { return t.s.appendRaw(dst) }
func (t NtfyTopic) secret() Secret             { return t.s }

// Secret returns the underlying opaque secret.
func (t NtfyTopic) Secret() Secret { return t.s }

// Opaque wraps a KeePass value that is staged verbatim into a file and never
// interpolated, so it needs no alphabet; it must be nonempty.
type Opaque struct{ s Secret }

// NewOpaque rejects only an empty value.
func NewOpaque(s Secret, label string) (Opaque, error) {
	if s.Empty() {
		return Opaque{}, &FormatError{Label: label}
	}
	return Opaque{s: s}, nil
}

func (o Opaque) secret() Secret { return o.s }
