// Package secret is the only package that can observe secret bytes.
//
// Every other package handles secrets through the opaque types defined here.
// They redact themselves under fmt, encoding/json, encoding.TextMarshaler and
// log/slog, and they leave the process only through the sinks in sink.go:
// a child's stdin pipe, a new private file inside an os.Root, or an explicit
// disclosure to this process's stdout for the commands whose contract is to
// print a secret.
package secret

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
)

// Redacted is what every formatting path prints instead of secret bytes.
const Redacted = "[REDACTED]"

// ErrDestroyed reports use of a secret after Destroy.
var ErrDestroyed = errors.New("secret: value was destroyed")

type box struct {
	data      []byte
	destroyed bool
}

// Secret is an opaque byte string. Copies share one backing buffer, so
// Destroy on any copy zeroises every copy.
type Secret struct {
	b *box
}

// FromBytes takes ownership of b: the bytes are copied into the secret and b
// is zeroised.
func FromBytes(b []byte) Secret {
	data := make([]byte, len(b))
	copy(data, b)
	clear(b)
	return Secret{b: &box{data: data}}
}

func (s Secret) bytes() []byte {
	if s.b == nil || s.b.destroyed {
		return nil
	}
	return s.b.data
}

// Len is the length in bytes.
func (s Secret) Len() int { return len(s.bytes()) }

// Empty reports whether the secret holds no bytes.
func (s Secret) Empty() bool { return s.Len() == 0 }

// Destroy zeroises the backing buffer. It is safe to call more than once.
func (s Secret) Destroy() {
	if s.b == nil {
		return
	}
	clear(s.b.data)
	s.b.data = nil
	s.b.destroyed = true
}

// Equal compares in constant time with respect to the contents.
func (s Secret) Equal(o Secret) bool {
	return subtle.ConstantTimeCompare(s.bytes(), o.bytes()) == 1
}

func (Secret) String() string               { return Redacted }
func (Secret) GoString() string             { return "secret.Secret{" + Redacted + "}" }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(Redacted)) }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (Secret) LogValue() slog.Value         { return slog.StringValue(Redacted) }
func (Secret) MarshalBinary() ([]byte, error) {
	return nil, errors.New("secret: binary marshalling refused")
}
func (*Secret) UnmarshalText([]byte) error { return errors.New("secret: text unmarshalling refused") }
func (*Secret) UnmarshalBinary([]byte) error {
	return errors.New("secret: binary unmarshalling refused")
}
func (*Secret) GobDecode([]byte) error    { return errors.New("secret: gob refused") }
func (Secret) GobEncode() ([]byte, error) { return nil, errors.New("secret: gob refused") }

// appendRaw is deliberately not appendTo: a raw Secret is not a Part.
func (s Secret) appendRaw(dst []byte) []byte { return append(dst, s.bytes()...) }
func (s Secret) secret() Secret              { return s }
func (s Secret) indexByte(c byte) int        { return indexByte(s.bytes(), c) }
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// Part is a fragment of a rendered secret file or payload. Only literals and
// validated secret types implement it, so an unvalidated KeePass value cannot
// be interpolated into an environment file.
type Part interface {
	appendTo(dst []byte) []byte
}

// Lit is a non-secret literal fragment.
type Lit string

func (l Lit) appendTo(dst []byte) []byte { return append(dst, l...) }

// Join renders parts into one new secret.
func Join(parts ...Part) Secret {
	var out []byte
	for _, p := range parts {
		out = p.appendTo(out)
	}
	return FromBytes(out)
}

// Holder is implemented by every type that wraps a Secret; it lets generic
// sinks accept validated newtypes without exposing their bytes.
type Holder interface {
	secret() Secret
}

// DestroyAll destroys every holder; nil-safe for zero values.
func DestroyAll(hs ...Holder) {
	for _, h := range hs {
		if h != nil {
			h.secret().Destroy()
		}
	}
}

// TrimTrailingNewlines drops every trailing "\n", as shell command
// substitution does for keepassxc-cli output. The result shares no buffer
// with s, which is destroyed.
func TrimTrailingNewlines(s Secret) Secret {
	b := s.bytes()
	end := len(b)
	for end > 0 && b[end-1] == '\n' {
		end--
	}
	out := FromBytes(b[:end])
	s.Destroy()
	return out
}
