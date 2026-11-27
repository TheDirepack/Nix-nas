package secret

import (
	"errors"
	"fmt"
	"os"
)

// Payload is the complete stdin a child process receives. It can only be
// fed into a StdinPipe, never into argv or the environment.
type Payload struct{ s Secret }

// Lines renders each holder followed by a newline, the keepassxc-cli and
// nas-secrets stdin convention.
func Lines(hs ...Holder) Payload {
	var out []byte
	for _, h := range hs {
		out = h.secret().appendRaw(out)
		out = append(out, '\n')
	}
	return Payload{s: FromBytes(out)}
}

// Destroy zeroises the rendered payload.
func (p Payload) Destroy() { p.s.Destroy() }

func (p Payload) secret() Secret { return p.s }

// StdinPipe is the write end of an OS pipe whose read end becomes a child's
// stdin. It is the only io.Writer secrets are ever written to.
type StdinPipe struct{ w *os.File }

// NewStdinPipe returns the secret write end and the read end for the child.
func NewStdinPipe() (*StdinPipe, *os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, fmt.Errorf("secret: stdin pipe: %w", err)
	}
	return &StdinPipe{w: w}, r, nil
}

// Close closes the write end without sending anything.
func (p *StdinPipe) Close() error { return p.w.Close() }

// Feed writes the payload and closes the pipe. A child that exits before
// reading everything yields EPIPE, which is reported but not fatal to the
// caller's interpretation of the child's own exit status.
func (p Payload) Feed(dst *StdinPipe) error {
	_, werr := dst.w.Write(p.s.bytes())
	cerr := dst.w.Close()
	return errors.Join(werr, cerr)
}

// WriteNewPrivateFile creates name inside root with mode 0600, refusing an
// existing file or a symlink, and writes the secret. os.Root confines the
// path to the staging directory.
func WriteNewPrivateFile(root *os.Root, name string, h Holder) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("secret: create %s: %w", name, err)
	}
	_, werr := f.Write(h.secret().bytes())
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

// DiscloseToStdout prints a secret for the commands whose documented
// contract is to print one (show-zfs-key, show-ntfy-password,
// show-authentik-bootstrap). It accepts no writer so it cannot be pointed at
// a log, buffer or file.
func DiscloseToStdout(prefix Lit, h Holder, suffix Lit) error {
	var out []byte
	out = prefix.appendTo(out)
	out = h.secret().appendRaw(out)
	out = suffix.appendTo(out)
	_, err := os.Stdout.Write(out)
	clear(out)
	return err
}
