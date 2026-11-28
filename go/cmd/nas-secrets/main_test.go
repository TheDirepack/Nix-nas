package main

import (
	"slices"
	"testing"
)

func TestCoordinationForwardsTerminationOnlyForBrowserActivation(t *testing.T) {
	for _, name := range []string{"activate-stdin", "activate", "activate-setup-stdin"} {
		got := coordinatorArgs("/runner", "/nas-secrets", name)
		want := []string{"/runner", "--action", "nas-secrets:" + name, "--class", "secrets", "--class", "runtime"}
		if name == "activate-stdin" {
			want = append(want, "--forward-termination")
		}
		want = append(want, "--", "/nas-secrets", name)
		if !slices.Equal(want, got) {
			t.Fatalf("%s: got %q want %q", name, got, want)
		}
	}
}
