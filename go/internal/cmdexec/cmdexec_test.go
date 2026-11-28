package cmdexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TheDirepack/Nix-nas/go/internal/secret"
)

func TestChildExitWithUnreadPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := secret.Lines(secret.FromBytes(make([]byte, 1<<20)))
	cmd := New("true").WithStdin(payload)
	result, err := NewOS().Run(ctx, cmd)
	if err != nil || !result.OK() {
		t.Fatalf("child exit: status %d, error %v", result.Code, err)
	}
}

func TestCancellationWithUnreadPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	payload := secret.Lines(secret.FromBytes(make([]byte, 1<<20)))
	_, err := NewOS().Run(ctx, New("sleep", Word("10")).WithStdin(payload))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("child cancellation: %v", err)
	}
}
