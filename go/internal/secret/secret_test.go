package secret

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

const canary = "hunter2-canary-value"

func TestSecretNeverFormats(t *testing.T) {
	s := FromBytes([]byte(canary))
	holder := struct {
		Name string
		Pw   Secret
		Ptr  *Secret
	}{"x", s, &s}
	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T"} {
		outputs = append(outputs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, holder), fmt.Sprintf(verb, &s))
	}
	js, err := json.Marshal(holder)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(js), fmt.Sprint(s), fmt.Sprintln(s), s.String(), s.GoString())
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("x", "pw", s, "holder", holder)
	slog.New(slog.NewTextHandler(&logged, nil)).Info("x", "pw", s)
	outputs = append(outputs, logged.String())
	for _, out := range outputs {
		if strings.Contains(out, canary) || strings.Contains(out, hex.EncodeToString([]byte(canary))) {
			t.Fatalf("secret leaked through formatting: %q", out)
		}
	}
	for _, typed := range []any{mustHex(t), mustAtom(t), KeePassPassword{s: s}, StrongKeePassPassword{p: KeePassPassword{s: s}}, Payload{s: s}} {
		encoded, err := json.Marshal(map[string]any{"secret": typed})
		if err != nil || strings.Contains(string(encoded), canary) || strings.Contains(string(encoded), "abcdef") {
			t.Fatal("typed secret wrapper leaked through JSON")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, typed); strings.Contains(out, canary) || strings.Contains(out, "abcdef") {
				t.Fatalf("validated wrapper leaked through %s: %q", verb, out)
			}
		}
	}
}

func mustHex(t *testing.T) HexKey {
	k, err := NewHexKey(FromBytes([]byte("abcdef0123456789")), 16, "k")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustAtom(t *testing.T) Atom {
	a, err := NewAtom(FromBytes([]byte(canary)), "a", 8, 64)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestUnmarshalIntoSecretIsRefused(t *testing.T) {
	var target struct{ Pw Secret }
	if err := json.Unmarshal([]byte(`{"Pw":"x"}`), &target); err == nil {
		t.Fatal("decoding into a Secret must fail")
	}
}

func TestDestroyZeroisesEveryCopy(t *testing.T) {
	raw := []byte(canary)
	s := FromBytes(raw)
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("FromBytes must zeroise its input")
	}
	backing := s.b.data
	alias := s
	s.Destroy()
	if !alias.Empty() || !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Fatal("Destroy must zeroise the shared buffer")
	}
	s.Destroy()
}

func TestAtomValidation(t *testing.T) {
	for _, ok := range []string{strings.Repeat("a", 20), strings.Repeat("0123456789abcdef", 4), "sk-live_ABC.def-123+/=:@~"} {
		if _, err := NewAtom(FromBytes([]byte(ok)), "t", 8, 4096); err != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"short", "safe\nEVIL=1", "safe\rEVIL=1", "safe\tvalue", "safe value with spaces",
		"'quoted-secret'", `"quoted-secret"`, "$(touch /tmp/x)", "`id`xxxxxxxx", "semi;colon", "pipe|value",
		`back\slash`, "control\x1fvalue", strings.Repeat("x", 4097), ""} {
		if _, err := NewAtom(FromBytes([]byte(bad)), "t", 8, 4096); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestHexValidation(t *testing.T) {
	if _, err := NewHexKey(FromBytes([]byte(strings.Repeat("a", 64))), 64, "k"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("g", 64), strings.Repeat("a", 32) + "\n" + strings.Repeat("b", 31)} {
		_, err := NewHexKey(FromBytes([]byte(bad)), 64, "key")
		var fe *FormatError
		if !errors.As(err, &fe) || strings.Contains(err.Error(), bad) {
			t.Errorf("hex %q: %v", bad, err)
		}
	}
}

func TestNtfyTopicAndTokens(t *testing.T) {
	for _, ok := range []string{"deadbeefcafebabe", "private_topic-123"} {
		if _, err := NewNtfyTopic(FromBytes([]byte(ok))); err != nil {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"topic\"\nuser = \"attacker:password\"", "topic/../../admin", "topic?x=1", "topic with space", strings.Repeat("x", 129), "short"} {
		if _, err := NewNtfyTopic(FromBytes([]byte(bad))); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := NewAPIToken(FromBytes([]byte("abcdefghij0123456789._~-")), "t"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"too-short", strings.Repeat("a", 19), strings.Repeat("a", 30) + "+", strings.Repeat("a", 30) + "\n"} {
		if _, err := NewAPIToken(FromBytes([]byte(bad)), "t"); err == nil {
			t.Errorf("accepted token %q", bad)
		}
	}
}

func TestReadLineBounds(t *testing.T) {
	r := bufio.NewReader(strings.NewReader(strings.Repeat("p", 4096) + "\nnext\n"))
	s, err := ReadLine(r, MaxLineRunes)
	if err != nil || s.Len() != 4096 {
		t.Fatalf("4096-character line: %v", err)
	}
	if next, err := ReadLine(r, MaxLineRunes); err != nil || !next.Equal(FromBytes([]byte("next"))) {
		t.Fatal("reader must stop at the newline")
	}
	for input, want := range map[string]error{
		strings.Repeat("p", 5000) + "\n":         LineTooLong,
		"no newline":                             LineMissing,
		"\n":                                     LineEmpty,
		"a\x00b\n":                               LineMalformed,
		"\xff\xfe\n":                             LineMalformed,
		strings.Repeat("é", 4096) + "\n":         nil,
		strings.Repeat("é", 4097) + "\n":         LineTooLong,
		strings.Repeat("\x80", 4*MaxLineRunes+1): LineTooLong,
	} {
		_, err := ReadLine(bufio.NewReader(strings.NewReader(input)), MaxLineRunes)
		if !errors.Is(err, want) && !(want == nil && err == nil) {
			t.Errorf("%.20q: got %v want %v", input, err, want)
		}
	}
}

func pw(t *testing.T, s string) KeePassPassword {
	p, err := NewKeePassPassword(FromBytes([]byte(s)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestStrengthFloor(t *testing.T) {
	if _, err := NewStrongKeePassPassword(pw(t, "correct horse battery staple"), nil); err != nil {
		t.Fatal(err)
	}
	for weak, want := range map[string]StrengthError{"short-pass": TooShort, "aaaaabbbbbaaaaabbbbb": TooFewDistinct} {
		if _, err := NewStrongKeePassPassword(pw(t, weak), nil); !errors.Is(err, want) {
			t.Errorf("%q: %v", weak, err)
		}
	}
	admin := FromBytes([]byte("same password for both"))
	if _, err := NewStrongKeePassPassword(pw(t, "Same Password For Both"), &admin); !errors.Is(err, SameAsAdministrator) {
		t.Fatalf("case-insensitive administrator match: %v", err)
	}
	// Full case folding, as Python's str.casefold: ß folds to ss.
	admin = FromBytes([]byte("strasse-password-1"))
	if _, err := NewStrongKeePassPassword(pw(t, "STRAßE-PASSWORD-1"), &admin); !errors.Is(err, SameAsAdministrator) {
		t.Fatalf("full case folding: %v", err)
	}
	// Length counts characters, not bytes.
	if _, err := NewStrongKeePassPassword(pw(t, "ééééééééabcdefg"), nil); !errors.Is(err, TooShort) {
		t.Fatalf("15 characters must be too short: %v", err)
	}
}

// Golden values computed by the retired Python implementation.
func TestVerifierMatchesPythonGolden(t *testing.T) {
	accounts := []AccountPassword{
		{Username: "nasadmin", Password: FromBytes([]byte("administrator-password"))},
		{Username: "älice", Password: FromBytes([]byte("p\"w\\é😀\x7f"))},
	}
	kp := pw(t, "keepass database passphrase ✓")
	salt, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	got, err := verifierDigest(kp.s, accounts, salt)
	if err != nil {
		t.Fatal(err)
	}
	if want := "b138ecd8807b3bb4976608c5f5d7e70271f75eb3a5b555cd7b27bf0bce5d6bea"; got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
	legacy := LegacyAuthenticators(kp, accounts)
	if legacy["nasadmin"] != "551bcb0650015fb07c3b465185e26ec1d765a870b8d1b2d2184b375a2641e852" ||
		legacy["älice"] != "71d77b8a759cd4b1452f2fc4ecf49a723e46966b1f42340995924737bf2a0572" {
		t.Fatalf("legacy authenticators differ: %v", legacy)
	}
	v, err := NewVerifier(kp, accounts)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := v.Matches(kp, accounts); !ok {
		t.Fatal("fresh verifier must match")
	}
	if ok, _ := v.Matches(pw(t, "another passphrase!!"), accounts); ok {
		t.Fatal("different KeePass password must not match")
	}
	for _, broken := range []Verifier{{}, {Algorithm: "sha256", Salt: v.Salt, Digest: v.Digest}, {Algorithm: v.Algorithm, Salt: "zz", Digest: v.Digest}} {
		if ok, _ := broken.Matches(kp, accounts); ok {
			t.Fatalf("malformed verifier matched: %+v", broken)
		}
	}
	js, _ := json.Marshal(v)
	if strings.Contains(string(js), legacy["nasadmin"]) {
		t.Fatal("verifier must not carry a legacy authenticator")
	}
}

func TestWriteNewPrivateFileRefusesExistingAndEscapes(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := WriteNewPrivateFile(root, "f", mustAtom(t)); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(filepath.Join(dir, "f"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if err := WriteNewPrivateFile(root, "f", mustAtom(t)); err == nil {
		t.Fatal("existing file must be refused")
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "../escape", "/abs"} {
		if err := WriteNewPrivateFile(root, name, mustAtom(t)); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
}

func TestJoinOnlyAcceptsValidatedParts(t *testing.T) {
	out := Join(Lit("K="), mustAtom(t), Lit("\n"))
	if !out.Equal(FromBytes([]byte("K=" + canary + "\n"))) {
		t.Fatal("join rendered incorrectly")
	}
}

func FuzzUnquoteJSONString(f *testing.F) {
	for _, seed := range []string{`"a"`, `"é"`, `"😀"`, `"\ud800"`, `"\n"`, `"a\"b"`, `"\/"`, "\"\x01\"", `"\x"`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := UnquoteJSONString(raw)
		var want string
		werr := json.Unmarshal(raw, &want)
		if err != nil {
			return
		}
		if werr != nil {
			t.Fatalf("accepted %q which encoding/json rejects: %v", raw, werr)
		}
		if !got.Equal(FromBytes([]byte(want))) {
			t.Fatalf("decoded %q differently from encoding/json", raw)
		}
		if !utf8.Valid(got.bytes()) {
			t.Fatalf("produced invalid UTF-8 from %q", raw)
		}
	})
}

func FuzzPythonJSONRoundTrip(f *testing.F) {
	for _, seed := range []string{"plain", "q\"b\\s", "é😀\x7f\x00\n\t"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !utf8.ValidString(s) {
			return
		}
		enc := appendPythonJSONString(nil, []byte(s))
		for _, c := range enc {
			if c < 0x20 || c > 0x7e {
				t.Fatalf("ensure_ascii output contains %#x", c)
			}
		}
		var back string
		if err := json.Unmarshal(enc, &back); err != nil || back != s {
			t.Fatalf("round trip of %q failed: %v", s, err)
		}
	})
}

func FuzzReadLine(f *testing.F) {
	f.Add([]byte("pw\nrest"), 8)
	f.Fuzz(func(t *testing.T, input []byte, limit int) {
		if limit < 1 || limit > 64 {
			return
		}
		r := bytes.NewReader(input)
		s, err := ReadLine(r, limit)
		if err != nil {
			return
		}
		b := s.bytes()
		if bytes.IndexByte(b, '\n') >= 0 || bytes.IndexByte(b, 0) >= 0 || !utf8.Valid(b) || utf8.RuneCount(b) > limit || len(b) == 0 {
			t.Fatalf("invalid line accepted from %q", input)
		}
		if consumed := len(input) - r.Len(); consumed != len(b)+1 {
			t.Fatalf("read past the newline: consumed %d of %q", consumed, input)
		}
	})
}

func TestInstallPrivateFileRefusesSymlinksAndAtomicallyReplacesDestination(t *testing.T) {
	source, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := source.WriteFile("token", []byte(canary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := source.Symlink("token", "link"); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if err := InstallPrivateFile(source, "link", target, "token", uid, gid, false); err == nil {
		t.Fatal("accepted a symlink source")
	}
	if err := InstallPrivateFile(nil, "", target, "token", uid, gid, false); err != nil {
		t.Fatal(err)
	}
	if err := InstallPrivateFile(source, "token", target, "token", uid, gid, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("non-replacing install: %v", err)
	}
	if err := InstallPrivateFile(source, "token", target, "token", uid, gid, true); err != nil {
		t.Fatal(err)
	}
	info, err := target.Stat("token")
	if err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("installed file: %v, %v", info, err)
	}
	if data, err := target.ReadFile("token"); err != nil || string(data) != canary {
		t.Fatal("installed token differs from source")
	}
}
