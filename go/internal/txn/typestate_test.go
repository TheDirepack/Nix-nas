package txn_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The cases below must not compile. They document what the typestate makes
// unrepresentable; the test builds each one and requires the named error.
var mustNotCompile = map[string]struct{ body, want string }{
	"commit before swap": {
		`var s *txn.Staged; s.Commit(context.Background())`, "s.Commit undefined",
	},
	"swap after swap": {
		`var w *txn.Swapped; w.Swap(context.Background())`, "w.Swap undefined",
	},
	"commit after rollback": {
		`var w *txn.Swapped; r := w.Abort(1); r.Commit(context.Background())`, "r.Commit undefined",
	},
	"post-commit evidence forged": {
		`_ = txn.Committed{}.Root(); var c txn.Committed = txn.Committed{c: nil}; _ = c`, "unexported field c",
	},
	"exit status out of range": {
		`var e txn.Exit = 256; _ = e`, "overflows",
	},
	"secret into argv": {
		`_ = cmdexec.New(cmdexec.KeePassXC, secret.Secret{})`, "does not implement cmdexec.Arg",
	},
	"secret into sudo stdin": {
		`_ = cmdexec.Root(cmdexec.Mv).WithStdin(secret.Payload{})`, "WithStdin undefined",
	},
	"raw string as env file part": {
		`var s secret.Secret; _ = secret.Join(secret.Lit("K="), s.String())`, "does not implement secret.Part",
	},
	"unvalidated secret as env file part": {
		`var s secret.Secret; _ = secret.Join(secret.Lit("K="), s)`, "does not implement secret.Part",
	},
	"opaque value interpolated": {
		`var o secret.Opaque; _ = secret.Join(o)`, "does not implement secret.Part",
	},
	"strong password forged": {
		`_ = secret.StrongKeePassPassword{}.Password(); _ = secret.StrongKeePassPassword{p: secret.KeePassPassword{}}`, "unexported field p",
	},
}

func goTool(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain unavailable")
	}
	return p
}

func TestTypestateRejectsMisuseAtCompileTime(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles one program per case")
	}
	gobin := goTool(t)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range mustNotCompile {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			mod := fmt.Sprintf("module github.com/TheDirepack/Nix-nas/go/typestateprobe\n\ngo 1.26.0\n\n"+
				"require github.com/TheDirepack/Nix-nas/go v0.0.0\n"+
				"replace github.com/TheDirepack/Nix-nas/go => %q\n", filepath.Join(wd, "../.."))
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o600); err != nil {
				t.Fatal(err)
			}
			src := "package probe\n\nimport (\n\t\"context\"\n\n" +
				"\t\"github.com/TheDirepack/Nix-nas/go/internal/cmdexec\"\n" +
				"\t\"github.com/TheDirepack/Nix-nas/go/internal/secret\"\n" +
				"\t\"github.com/TheDirepack/Nix-nas/go/internal/txn\"\n)\n\n" +
				"var _ = context.Background\nvar _ cmdexec.Arg\nvar _ secret.Secret\nvar _ txn.Exit\n\n" +
				"func probe() {\n\t" + c.body + "\n}\n"
			if err := os.WriteFile(filepath.Join(dir, "probe.go"), []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(gobin, "build", "-mod=mod", "-o", os.DevNull, ".") // #nosec G204 -- test toolchain
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("misuse compiled:\n%s", c.body)
			}
			if !strings.Contains(string(out), c.want) {
				t.Fatalf("expected %q in:\n%s", c.want, out)
			}
		})
	}
}
