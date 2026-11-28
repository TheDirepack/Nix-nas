package unlockapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/cmdexec"
	"github.com/TheDirepack/Nix-nas/go/internal/keepass"
	"github.com/TheDirepack/Nix-nas/go/internal/secret"
	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// Service limits.
const (
	SocketTimeout          = 30 * time.Second
	MaxConnections         = 8
	FailureBackoffBase     = 5 * time.Second
	FailureBackoffMax      = 300 * time.Second
	DefaultActivationLimit = 900 * time.Second
	// TerminationGrace bounds how long a timed-out nas-secrets may roll back
	// after SIGTERM before it is killed.
	TerminationGrace = 180 * time.Second
)

// Outcome is the result of one activation attempt. The HTTP mapping in
// Outcome.status is checked for exhaustiveness by the exhaustive linter.
type Outcome int

const (
	// Activated means nas-secrets exited 0.
	Activated Outcome = iota
	// WrongPassword means KeePassXC refused the password.
	WrongPassword
	// RolledBack means activation failed and nas-secrets rolled back.
	RolledBack
	// TimedOut means activation exceeded its limit.
	TimedOut
)

func (o Outcome) status() int {
	switch o {
	case Activated:
		return http.StatusOK
	case WrongPassword:
		return http.StatusUnauthorized
	case RolledBack:
		return http.StatusInternalServerError
	case TimedOut:
		return http.StatusGatewayTimeout
	}
	panic(fmt.Sprintf("unlockapi: unmapped outcome %d", int(o)))
}

// Result carries an outcome and the nas-secrets exit status for messages.
type Result struct {
	Outcome Outcome
	Code    int
}

func (r Result) message() string {
	switch r.Outcome {
	case Activated:
		return ""
	case WrongPassword:
		return "The KeePass database password was not accepted."
	case RolledBack:
		return fmt.Sprintf("Activation failed (status %d) and was rolled back; the NAS stays locked. "+
			"Inspect `journalctl -t nas-unlock-api` or unlock from the recovery console.", r.Code)
	case TimedOut:
		return "Unlock timed out; inspect the appliance journal."
	}
	return "Unlock failed."
}

// Logger receives journal lines; it never receives secrets.
type Logger interface{ Notice(msg string) }

// Activator runs `nas-secrets activate-stdin`.
type Activator interface {
	Activate(ctx context.Context, pw secret.KeePassPassword) Result
}

// Host is the system the service observes and restores.
type Host struct {
	SecretReady  syspath.Abs
	SetupState   syspath.Abs
	NASSecrets   cmdexec.Program
	Systemctl    cmdexec.Program
	Runner       cmdexec.Runner
	Log          Logger
	ActivationIn time.Duration
}

// Locked reports a missing ready marker.
func (h *Host) Locked() bool {
	st, err := os.Stat(h.SecretReady.String())
	return err != nil || !st.Mode().IsRegular()
}

// SetupComplete reports the setup state file.
func (h *Host) SetupComplete() bool {
	st, err := os.Stat(h.SetupState.String())
	return err == nil && st.Mode().IsRegular()
}

// Activate implements Activator. On timeout nas-secrets receives SIGTERM so
// that it can roll back; it is killed only after TerminationGrace.
func (h *Host) Activate(ctx context.Context, pw secret.KeePassPassword) Result {
	limit := h.ActivationIn
	if limit <= 0 {
		limit = DefaultActivationLimit
	}
	runCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	c := cmdexec.New(h.NASSecrets, cmdexec.Word("activate-stdin")).
		WithTerminationGroup().WithStdin(secret.Lines(pw)).Stdout(cmdexec.Capture).Stderr(cmdexec.Capture)
	res, err := h.Runner.Run(runCtx, c)
	if errors.Is(err, context.DeadlineExceeded) || runCtx.Err() != nil {
		h.Log.Notice("nas-unlock-api: nas-secrets activate-stdin timed out")
		return Result{Outcome: TimedOut}
	}
	if err == nil && res.OK() {
		return Result{Outcome: Activated}
	}
	// nas-secrets never prints secret values; keep the tail for the journal.
	lines := bytes.Split(bytes.TrimSpace(res.Stderr), []byte("\n"))
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	for _, line := range lines {
		if len(line) > 500 {
			line = line[:500]
		}
		if len(line) > 0 {
			h.Log.Notice("nas-unlock-api: nas-secrets: " + string(line))
		}
	}
	if bytes.Contains(res.Stderr, []byte(keepass.WrongPasswordMarker)) {
		return Result{Outcome: WrongPassword, Code: res.Code}
	}
	return Result{Outcome: RolledBack, Code: res.Code}
}

// RestoreLockedIdentity restarts the pre-unlock Authentik layer, which a
// rolled-back activation stops through PartOf= on the protected target.
func (h *Host) RestoreLockedIdentity(ctx context.Context) {
	if !h.Locked() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	_, _ = h.Runner.Run(ctx, cmdexec.New(h.Systemctl, cmdexec.Word("start"),
		syspath.MustUnit("authentik-worker.service"), syspath.MustUnit("authentik.service"),
		syspath.MustUnit("nas-authentik-proxy-outpost.service")))
}

// Throttle is single-flight activation with exponential delay after
// failures. KDBX key derivation already slows each guess; this bounds how
// fast an authenticated session can drive guesses through root.
type Throttle struct {
	mu       sync.Mutex
	now      func() time.Time
	running  bool
	failures int
	until    time.Time
}

// NewThrottle uses clock, or time.Now when nil.
func NewThrottle(clock func() time.Time) *Throttle {
	if clock == nil {
		clock = time.Now
	}
	return &Throttle{now: clock}
}

func ceilSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// RetryAfter is the remaining backoff in whole seconds.
func (t *Throttle) RetryAfter() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return ceilSeconds(t.until.Sub(t.now()))
}

// Busy reports a running attempt.
func (t *Throttle) Busy() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// Slot is held for the duration of one attempt.
type Slot struct {
	t    *Throttle
	done bool
}

// Acquire claims the single flight slot.
func (t *Throttle) Acquire() (*Slot, *apiError) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil, reject(http.StatusConflict, "An unlock attempt is already running.")
	}
	if wait := t.until.Sub(t.now()); wait > 0 {
		s := ceilSeconds(wait)
		return nil, &apiError{status: http.StatusTooManyRequests, retryAfter: s,
			msg: fmt.Sprintf("Too many failed unlock attempts; retry in %d seconds.", s)}
	}
	t.running = true
	return &Slot{t: t}, nil
}

// Release ends the attempt and updates the backoff.
func (s *Slot) Release(succeeded bool) {
	if s.done {
		panic("unlockapi: slot released twice")
	}
	s.done = true
	t := s.t
	t.mu.Lock()
	defer t.mu.Unlock()
	t.running = false
	if succeeded {
		t.failures = 0
		t.until = time.Time{}
		return
	}
	t.failures++
	delay := FailureBackoffMax
	if t.failures <= 7 {
		delay = min(FailureBackoffBase<<(t.failures-1), FailureBackoffMax)
	}
	t.until = t.now().Add(delay)
}

// Server is the HTTP handler.
type Server struct {
	Host      *Host
	Activator Activator
	Throttle  *Throttle
}

type statusDocument struct {
	Busy              bool `json:"busy"`
	Locked            bool `json:"locked"`
	RetryAfterSeconds int  `json:"retryAfterSeconds"`
	SetupComplete     bool `json:"setupComplete"`
}

type unlockedDocument struct {
	Locked   bool `json:"locked"`
	Unlocked bool `json:"unlocked"`
}

type errorDocument struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any, retryAfter int) {
	body, _ := json.Marshal(v)
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	if retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(retryAfter))
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, e *apiError) {
	writeJSON(w, e.status, errorDocument{Error: e.msg}, e.retryAfter)
}

// ServeHTTP routes the two endpoints.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/unlock/api/status" && r.URL.RawQuery == "":
		writeJSON(w, http.StatusOK, statusDocument{
			Busy: s.Throttle.Busy(), Locked: s.Host.Locked(),
			RetryAfterSeconds: s.Throttle.RetryAfter(), SetupComplete: s.Host.SetupComplete(),
		}, 0)
	case r.Method == http.MethodPost && r.URL.Path == "/unlock/api/activate" && r.URL.RawQuery == "":
		s.activate(w, r)
	default:
		writeError(w, reject(http.StatusNotFound, "Not found"))
	}
}

func (s *Server) activate(w http.ResponseWriter, r *http.Request) {
	session, aerr := authorize(r)
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	req, aerr := readUnlockRequest(r)
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	defer req.Destroy()
	if !s.Host.SetupComplete() {
		writeError(w, reject(http.StatusConflict, "First-start setup is not complete."))
		return
	}
	if !s.Host.Locked() {
		writeJSON(w, http.StatusOK, unlockedDocument{Locked: false, Unlocked: true}, 0)
		return
	}
	slot, aerr := s.Throttle.Acquire()
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	s.Host.Log.Notice(fmt.Sprintf("nas-unlock-api: unlock attempt by Authentik user %q", session.User()))
	// The activation must finish even if the browser disconnects.
	result := s.Activator.Activate(context.WithoutCancel(r.Context()), req.Password())
	req.Destroy()
	slot.Release(result.Outcome == Activated)
	switch result.Outcome {
	case Activated:
		s.Host.Log.Notice(fmt.Sprintf("nas-unlock-api: unlocked by Authentik user %q", session.User()))
		writeJSON(w, http.StatusOK, unlockedDocument{Locked: false, Unlocked: true}, 0)
	case WrongPassword, RolledBack, TimedOut:
		s.Host.RestoreLockedIdentity(context.WithoutCancel(r.Context()))
		writeError(w, reject(result.Outcome.status(), result.message()))
	}
}

// PeerListener admits only Unix-socket peers whose SO_PEERCRED uid is
// allowed, and at most MaxConnections at once; others are closed unread.
type PeerListener struct {
	net.Listener
	Allowed map[uint32]bool
	gate    chan struct{}
}

// NewPeerListener wraps a Unix listener.
func NewPeerListener(l net.Listener, allowed map[uint32]bool) *PeerListener {
	return &PeerListener{Listener: l, Allowed: allowed, gate: make(chan struct{}, MaxConnections)}
}

func peerUID(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var serr error
	if err := raw.Control(func(fd uintptr) {
		cred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED) // #nosec -- fd fits int
	}); err != nil || serr != nil {
		return 0, false
	}
	return cred.Uid, true
}

type gatedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (g *gatedConn) Close() error {
	err := g.Conn.Close()
	g.once.Do(g.release)
	return err
}

// Accept returns the next admitted connection.
func (l *PeerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, ok := peerUID(c)
		if !ok || !l.Allowed[uid] {
			_ = c.Close()
			continue
		}
		select {
		case l.gate <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		return &gatedConn{Conn: c, release: func() { <-l.gate }}, nil
	}
}

// NewHTTPServer applies the HTTP/1.0-style connection policy.
func NewHTTPServer(h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: SocketTimeout,
		ReadTimeout:       SocketTimeout,
		IdleTimeout:       SocketTimeout,
		MaxHeaderBytes:    16 << 10,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}
