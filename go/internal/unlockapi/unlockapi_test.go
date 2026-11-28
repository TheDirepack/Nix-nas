package unlockapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
)

func TestBackoffDoublesCapsAndResets(t *testing.T) {
	now := time.Unix(100, 0)
	th := NewThrottle(func() time.Time { return now })
	slot, err := th.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, busy := th.Acquire(); busy == nil || busy.status != http.StatusConflict {
		t.Fatal("a second attempt must be refused as busy")
	}
	slot.Release(false)
	if got := th.RetryAfter(); got != 5 {
		t.Fatalf("first backoff %d", got)
	}
	if _, e := th.Acquire(); e == nil || e.status != http.StatusTooManyRequests || e.retryAfter != 5 {
		t.Fatalf("throttled attempt: %+v", e)
	}
	now = now.Add(5 * time.Second)
	slot, _ = th.Acquire()
	slot.Release(false)
	if got := th.RetryAfter(); got != 10 {
		t.Fatalf("second backoff %d", got)
	}
	for range 30 {
		now = now.Add(FailureBackoffMax)
		slot, _ = th.Acquire()
		slot.Release(false)
	}
	if got := th.RetryAfter(); got != int(FailureBackoffMax.Seconds()) {
		t.Fatalf("capped backoff %d", got)
	}
	now = now.Add(FailureBackoffMax)
	slot, _ = th.Acquire()
	slot.Release(true)
	if th.RetryAfter() != 0 {
		t.Fatal("success must reset the backoff")
	}
}

func TestGroupHeaderParsing(t *testing.T) {
	for header, want := range map[string]bool{
		"users|nas_admin": true, "nas_admin, users": true, "nas_admins|users": false, "": false, "nas_administrators": false,
	} {
		if GroupsIncludeAdmin(header) != want {
			t.Errorf("%q", header)
		}
	}
}

func TestOutcomeMappingIsExhaustive(t *testing.T) {
	want := map[Outcome]int{Activated: 200, WrongPassword: 401, RolledBack: 500, TimedOut: 504}
	for o, status := range want {
		if o.status() != status {
			t.Errorf("%d -> %d", o, o.status())
		}
	}
}

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		host, origin string
		ok           bool
	}{
		{"nas.local:8443", "https://nas.local:8443", true},
		{"nas.local", "https://nas.local", true},
		{"nas.local", "https://nas.local:443", true},
		{"NAS.local:8443", "https://nas.LOCAL:8443", true},
		{"[fd00::1]:8443", "https://[fd00::1]:8443", true},
		{"nas.local:8443", "http://nas.local:8443", false},
		{"nas.local:8443", "https://evil.example", false},
		{"nas.local:8443", "null", false},
		{"nas.local:8443", "", false},
		{"nas local", "https://nas local", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/unlock/api/activate", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if got := sameOrigin(r) == nil; got != c.ok {
			t.Errorf("%s / %s: %v", c.host, c.origin, got)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Host = "nas.local"
	r.Header.Add("Origin", "https://nas.local")
	r.Header.Add("Origin", "https://nas.local")
	if sameOrigin(r) == nil {
		t.Error("duplicate Origin headers must be refused")
	}
}

func TestBodyContract(t *testing.T) {
	cases := map[string]int{
		`{"password":"correct horse"}`: 0,
		`{"password":"café 😀"}`:        0,
		`{not json`:                    400,
		`["password"]`:                 400,
		`{"password":"x","extra":1}`:   400,
		`{"password":""}`:              400,
		`{"password":"a\nb"}`:          400,
		`{"password":"a\u0000b"}`:      400,
		`{"password":"a\u007fb"}`:      400,
		`{"password":5}`:               400,
		`{"password":null}`:            400,
		`{"password":"\ud800"}`:        400,
		`{}`:                           400,
		`{"password":"` + strings.Repeat("x", 4097) + `"}`: 400,
		`{"password":"` + strings.Repeat("é", 4096) + `"}`: 0,
	}
	for body, want := range cases {
		req, err := parseUnlockBody([]byte(body))
		switch {
		case want == 0 && err != nil:
			t.Errorf("%.40s rejected: %v", body, err)
		case want != 0 && (err == nil || err.status != want):
			t.Errorf("%.40s: %v", body, err)
		}
		if err == nil {
			req.Destroy()
		}
	}
	if _, err := parseUnlockBody([]byte("\xff")); err == nil {
		t.Error("invalid UTF-8 must be rejected")
	}
}

type fakeRunner struct {
	res cmdexec.Result
	err error
	got []string
}

func (f *fakeRunner) Run(_ context.Context, c cmdexec.Command) (cmdexec.Result, error) {
	f.got = append(f.got, strings.Join(c.Argv(), " "))
	return f.res, f.err
}
func (f *fakeRunner) RunSecret(context.Context, cmdexec.Command) (secret.Secret, cmdexec.Result, error) {
	panic("unused")
}
func (f *fakeRunner) RunRoot(context.Context, cmdexec.Privileged) (cmdexec.Result, error) {
	panic("the unlock API never escalates")
}

type nopLog struct{ lines []string }

func (n *nopLog) Notice(m string) { n.lines = append(n.lines, m) }

func TestActivatorMapsStatusesAndLogsOnlyTheTail(t *testing.T) {
	pw, _ := secret.NewKeePassPassword(secret.FromBytes([]byte("pw")))
	for _, c := range []struct {
		res  cmdexec.Result
		err  error
		want Outcome
	}{
		{cmdexec.Result{Code: 0}, nil, Activated},
		{cmdexec.Result{Code: 1, Stderr: []byte("Unable to unlock the KeePassXC database.\n")}, nil, WrongPassword},
		{cmdexec.Result{Code: 71, Stderr: []byte("Protected service target failed to start\n")}, nil, RolledBack},
		{cmdexec.Result{Code: 143}, context.DeadlineExceeded, TimedOut},
	} {
		log := &nopLog{}
		h := &Host{NASSecrets: "nas-secrets", Runner: &fakeRunner{res: c.res, err: c.err}, Log: log}
		if got := h.Activate(context.Background(), pw); got.Outcome != c.want {
			t.Errorf("%+v -> %v", c.res, got.Outcome)
		}
	}
}

func FuzzParseUnlockBody(f *testing.F) {
	for _, s := range []string{`{"password":"x"}`, `{"password":"é"}`, `{"a":1}`, `{"password":"x","password":"y"}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		req, err := parseUnlockBody(body)
		if err != nil {
			return
		}
		defer req.Destroy()
		var doc map[string]any
		if json.Unmarshal(body, &doc) != nil || len(doc) != 1 {
			t.Fatalf("accepted non-conforming body %q", body)
		}
		s, ok := doc["password"].(string)
		if !ok || s == "" || len([]rune(s)) > secret.MaxLineRunes {
			t.Fatalf("accepted invalid password in %q", body)
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("accepted control character in %q", body)
			}
		}
	})
}
