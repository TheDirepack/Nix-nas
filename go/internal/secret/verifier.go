package secret

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

// VerifierAlgorithm names the only accepted journal password verifier.
const VerifierAlgorithm = "scrypt-n32768-r8-p1"

// AccountPassword binds a non-secret username to its secret password.
type AccountPassword struct {
	Username string
	Password Secret
}

// Verifier is the non-secret journal record. It is safe to persist: the
// digest is memory-hard and salted per journal.
type Verifier struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Digest    string `json:"digest"`
}

func sortedInputs(accounts []AccountPassword) []AccountPassword {
	out := slices.Clone(accounts)
	// Python sorts (username, password) tuples; UTF-8 byte order equals code
	// point order.
	slices.SortFunc(out, func(a, b AccountPassword) int {
		if c := bytes.Compare([]byte(a.Username), []byte(b.Username)); c != 0 {
			return c
		}
		return bytes.Compare(a.Password.bytes(), b.Password.bytes())
	})
	return out
}

// appendPythonJSONString matches json.dumps(ensure_ascii=True).
func appendPythonJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	for len(s) > 0 {
		r, size := utf8.DecodeRune(s)
		s = s[size:]
		switch {
		case r == '"':
			dst = append(dst, '\\', '"')
		case r == '\\':
			dst = append(dst, '\\', '\\')
		case r == '\n':
			dst = append(dst, '\\', 'n')
		case r == '\r':
			dst = append(dst, '\\', 'r')
		case r == '\t':
			dst = append(dst, '\\', 't')
		case r == '\b':
			dst = append(dst, '\\', 'b')
		case r == '\f':
			dst = append(dst, '\\', 'f')
		case r >= 0x20 && r <= 0x7e:
			dst = append(dst, byte(r))
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			dst = fmt.Appendf(dst, `\u%04x\u%04x`, hi, lo)
		default:
			dst = fmt.Appendf(dst, `\u%04x`, r)
		}
	}
	return append(dst, '"')
}

// verifierMaterial is json.dumps({"keepass": ..., "accounts": sorted(...)},
// sort_keys=True, separators=(",", ":")).
func verifierMaterial(keepass Secret, accounts []AccountPassword) []byte {
	out := []byte(`{"accounts":[`)
	for i, a := range sortedInputs(accounts) {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '[')
		out = appendPythonJSONString(out, []byte(a.Username))
		out = append(out, ',')
		out = appendPythonJSONString(out, a.Password.bytes())
		out = append(out, ']')
	}
	out = append(out, `],"keepass":`...)
	out = appendPythonJSONString(out, keepass.bytes())
	return append(out, '}')
}

func verifierDigest(keepass Secret, accounts []AccountPassword, salt []byte) (string, error) {
	material := verifierMaterial(keepass, accounts)
	defer clear(material)
	key, err := scrypt.Key(material, salt, 1<<15, 8, 1, 32)
	if err != nil {
		return "", fmt.Errorf("secret: scrypt: %w", err)
	}
	return hex.EncodeToString(key), nil
}

// NewVerifier salts and derives a fresh journal verifier.
func NewVerifier(keepass KeePassPassword, accounts []AccountPassword) (Verifier, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Verifier{}, fmt.Errorf("secret: random source: %w", err)
	}
	digest, err := verifierDigest(keepass.s, accounts, salt)
	if err != nil {
		return Verifier{}, err
	}
	return Verifier{Algorithm: VerifierAlgorithm, Salt: hex.EncodeToString(salt), Digest: digest}, nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if ('0' > c || c > '9') && ('a' > c || c > 'f') {
			return false
		}
	}
	return true
}

// Matches recomputes the digest; malformed verifiers never match.
func (v Verifier) Matches(keepass KeePassPassword, accounts []AccountPassword) (bool, error) {
	if v.Algorithm != VerifierAlgorithm || !isLowerHex(v.Salt, 32) {
		return false, nil
	}
	salt, err := hex.DecodeString(v.Salt)
	if err != nil {
		return false, nil
	}
	expected, err := verifierDigest(keepass.s, accounts, salt)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(v.Digest)) == 1, nil
}

// LegacyAuthenticators recomputes the retired unsalted v2 authenticators
// only so that an older journal can be recognized and migrated.
func LegacyAuthenticators(keepass KeePassPassword, accounts []AccountPassword) map[string]string {
	h := sha256.New()
	h.Write([]byte("nixos-nas/setup-password-fingerprint/v2\x00"))
	h.Write(keepass.s.bytes())
	key := h.Sum(nil)
	defer clear(key)
	out := map[string]string{}
	for _, a := range sortedInputs(accounts) {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(a.Username))
		mac.Write([]byte{0})
		mac.Write(a.Password.bytes())
		out[a.Username] = hex.EncodeToString(mac.Sum(nil))
	}
	return out
}

var errInvalidJSONString = errors.New("secret: invalid JSON string")

// UnquoteJSONString decodes one JSON string token into a secret without an
// intermediate Go string. Invalid escapes, lone surrogates, raw control
// characters and invalid UTF-8 are rejected.
func UnquoteJSONString(raw []byte) (Secret, error) {
	bad := errInvalidJSONString
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return Secret{}, bad
	}
	in := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(in))
	fail := func() (Secret, error) { clear(out); return Secret{}, bad }
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == '"' || c < 0x20:
			return fail()
		case c != '\\':
			r, size := utf8.DecodeRune(in[i:])
			if r == utf8.RuneError && size <= 1 {
				return fail()
			}
			out = append(out, in[i:i+size]...)
			i += size
			continue
		}
		if i+1 >= len(in) {
			return fail()
		}
		esc := in[i+1]
		i += 2
		switch esc {
		case '"', '\\', '/':
			out = append(out, esc)
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(in, i)
			if !ok {
				return fail()
			}
			i += 4
			if utf16.IsSurrogate(r) {
				if r >= 0xdc00 || i+6 > len(in) || in[i] != '\\' || in[i+1] != 'u' {
					return fail()
				}
				lo, ok := hex4(in, i+2)
				if !ok || lo < 0xdc00 || lo > 0xdfff {
					return fail()
				}
				i += 6
				r = utf16.DecodeRune(r, lo)
			}
			out = utf8.AppendRune(out, r)
		default:
			return fail()
		}
	}
	return FromBytes(out), nil
}

func hex4(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var v rune
	for _, c := range b[at : at+4] {
		switch {
		case '0' <= c && c <= '9':
			v = v<<4 | rune(c-'0')
		case 'a' <= c && c <= 'f':
			v = v<<4 | rune(c-'a'+10)
		case 'A' <= c && c <= 'F':
			v = v<<4 | rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return v, true
}
