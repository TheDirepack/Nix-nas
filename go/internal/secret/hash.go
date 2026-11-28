package secret

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters for the Vaultwarden admin token: t=3, m=64 MiB, p=4.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	bcryptCost   = 12
)

// PHC is an encoded Argon2id digest suitable for Vaultwarden's ADMIN_TOKEN.
type PHC struct{ s Secret }

// Argon2idPHC hashes a validated atom with a fresh salt.
func Argon2idPHC(a Atom) (PHC, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PHC{}, fmt.Errorf("secret: random source: %w", err)
	}
	key := argon2.IDKey(a.s.bytes(), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	out := fmt.Appendf(nil, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(key))
	clear(key)
	return PHC{s: FromBytes(out)}, nil
}

func (p PHC) appendTo(dst []byte) []byte { return p.s.appendRaw(dst) }
func (p PHC) secret() Secret             { return p.s }

// BcryptHash is an encoded bcrypt digest for ntfy's NTFY_AUTH_USERS.
type BcryptHash struct{ s Secret }

// Bcrypt hashes a validated atom at cost 12.
func Bcrypt(a Atom) (BcryptHash, error) {
	out, err := bcrypt.GenerateFromPassword(a.s.bytes(), bcryptCost)
	if err != nil {
		return BcryptHash{}, fmt.Errorf("secret: bcrypt: %w", err)
	}
	return BcryptHash{s: FromBytes(out)}, nil
}

func (b BcryptHash) appendTo(dst []byte) []byte { return b.s.appendRaw(dst) }
func (b BcryptHash) secret() Secret             { return b.s }
