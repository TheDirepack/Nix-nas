// Package unlockapi is the Authentik-gated browser unlock service. Caddy
// routes /unlock/api/* here only in the locked configuration, after
// forward-auth and a nas_admin group check; this package re-checks both.
package unlockapi

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/TheDirepack/Nix-nas/go/internal/secret"
)

// Request contract constants.
const (
	MaxBodyBytes = 8192
	AdminGroup   = "nas_admin"
)

// AuthentikUser is the single forward-auth Remote-User value.
type AuthentikUser struct{ name string }

func (u AuthentikUser) String() string { return u.name }

// AdminSession can only be built by authorize, after the same-origin check
// and the nas_admin group check both passed.
type AdminSession struct{ user AuthentikUser }

// User is the authenticated Authentik user.
func (s AdminSession) User() AuthentikUser { return s.user }

// UnlockRequest is a validated body: exactly one bounded single-line
// password and nothing else.
type UnlockRequest struct{ password secret.KeePassPassword }

// Password hands the password to the activator.
func (r UnlockRequest) Password() secret.KeePassPassword { return r.password }

// Destroy zeroises the password.
func (r UnlockRequest) Destroy() { r.password.Destroy() }

// apiError is a rejected request with its HTTP status.
type apiError struct {
	status     int
	msg        string
	retryAfter int
}

func (e *apiError) Error() string { return e.msg }

func reject(status int, msg string) *apiError { return &apiError{status: status, msg: msg} }

var authorityPattern = regexp.MustCompile(`^([a-z0-9_.-]+|\[[0-9a-f:.]+\])(?::([0-9]+))?$`)

func sameOrigin(r *http.Request) *apiError {
	denied := reject(http.StatusForbidden, "Unlock requests must come from the unlock page.")
	origins := r.Header.Values("Origin")
	if len(origins) != 1 || r.Host == "" {
		return denied
	}
	m := authorityPattern.FindStringSubmatch(strings.ToLower(r.Host))
	if m == nil {
		return denied
	}
	hostname, port := m[1], m[2]
	expected := "https://" + hostname
	origin := strings.ToLower(origins[0])
	if port == "" || port == "443" {
		if origin == expected || origin == expected+":443" {
			return nil
		}
		return denied
	}
	if origin == expected+":"+port {
		return nil
	}
	return denied
}

// GroupsIncludeAdmin parses the forward-auth group list ("a|b" or "a, b").
func GroupsIncludeAdmin(header string) bool {
	for _, item := range strings.FieldsFunc(header, func(r rune) bool { return r == '|' || r == ',' }) {
		if strings.TrimSpace(item) == AdminGroup {
			return true
		}
	}
	return false
}

func authorize(r *http.Request) (AdminSession, *apiError) {
	if err := sameOrigin(r); err != nil {
		return AdminSession{}, err
	}
	users := r.Header.Values("Remote-User")
	groups := r.Header.Values("Remote-Groups")
	if len(users) != 1 || users[0] == "" || len(groups) != 1 || !GroupsIncludeAdmin(groups[0]) {
		return AdminSession{}, reject(http.StatusForbidden, "Unlocking requires an Authentik nas_admin session.")
	}
	return AdminSession{user: AuthentikUser{name: users[0]}}, nil
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// readUnlockRequest enforces the body contract before reading more than
// Content-Length bytes, and never more than MaxBodyBytes.
func readUnlockRequest(r *http.Request) (UnlockRequest, *apiError) {
	if len(r.TransferEncoding) > 0 || len(r.Header.Values("Transfer-Encoding")) > 0 {
		return UnlockRequest{}, reject(http.StatusBadRequest, "Transfer-Encoding is not supported.")
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	if ct != "application/json" {
		return UnlockRequest{}, reject(http.StatusUnsupportedMediaType, "Unlock requests must be JSON.")
	}
	lengths := r.Header.Values("Content-Length")
	if len(lengths) != 1 || !isDigits(strings.TrimSpace(lengths[0])) {
		return UnlockRequest{}, reject(http.StatusLengthRequired, "Unlock requests require one Content-Length header.")
	}
	if r.ContentLength > MaxBodyBytes || len(strings.TrimSpace(lengths[0])) > 6 {
		return UnlockRequest{}, reject(http.StatusRequestEntityTooLarge, "Unlock request is too large.")
	}
	body := make([]byte, r.ContentLength)
	defer clear(body)
	if _, err := io.ReadFull(r.Body, body); err != nil {
		return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request was truncated.")
	}
	return parseUnlockBody(body)
}

func parseUnlockBody(body []byte) (UnlockRequest, *apiError) {
	if !utf8.Valid(body) {
		return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request is not valid JSON.")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		var probe any
		if json.Unmarshal(body, &probe) == nil {
			return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request must contain only the password.")
		}
		return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request is not valid JSON.")
	}
	raw, ok := fields["password"]
	defer func() {
		for _, v := range fields {
			clear(v)
		}
	}()
	if !ok || len(fields) != 1 {
		return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request must contain only the password.")
	}
	enter := reject(http.StatusBadRequest, "Enter the KeePass database password.")
	if len(raw) == 0 || raw[0] != '"' {
		return UnlockRequest{}, enter
	}
	value, err := secret.UnquoteJSONString(raw)
	if err != nil {
		return UnlockRequest{}, reject(http.StatusBadRequest, "Unlock request is not valid JSON.")
	}
	switch {
	case value.Empty():
		return UnlockRequest{}, enter
	case value.RuneCount() > secret.MaxLineRunes:
		value.Destroy()
		return UnlockRequest{}, reject(http.StatusBadRequest, "The KeePass database password is too long.")
	case value.HasControl():
		value.Destroy()
		return UnlockRequest{}, reject(http.StatusBadRequest, "The KeePass database password must be a single line without control characters.")
	}
	pw, perr := secret.NewKeePassPassword(value)
	if perr != nil {
		value.Destroy()
		return UnlockRequest{}, enter
	}
	return UnlockRequest{password: pw}, nil
}
