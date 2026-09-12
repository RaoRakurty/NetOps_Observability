// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package main

// keys_test.go — the operator surface of the embedded-key guard (tracker 259).
//
// `keys` is what a human runs to see what the binary in front of them trusts;
// `keys --release-check` is what a release step runs to REFUSE while the lab key
// is the only key embedded. The two must not drift apart: printing must never be
// a refusal, and the refusal must be a non-zero exit, not a line of output that
// scrolls past.

import (
	"strings"
	"testing"

	"netops/backend/internal/licence"
)

func TestKeysPrintsTheTrustedSetWithItsPurpose(t *testing.T) {
	out, err := capture(t, "keys")
	if err != nil {
		t.Fatalf("keys refused without --release-check: %v\n%s", err, out)
	}
	for _, want := range []string{"embedded signing keys", "role=", "purpose="} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not mention %q:\n%s", want, out)
		}
	}
	for _, k := range licence.EmbeddedKeys() {
		if !strings.Contains(out, k.ID) {
			t.Errorf("output omits embedded key %s:\n%s", k.ID, out)
		}
		if !strings.Contains(out, k.Base64) {
			t.Errorf("output omits the base64 of key %s, which is what a customer verifies with:\n%s", k.ID, out)
		}
	}
}

// TestKeysReleaseCheckMatchesReleaseReady ties the exit code to the library
// answer in both directions, so this test keeps working when the production key
// lands instead of having to be rewritten.
func TestKeysReleaseCheckMatchesReleaseReady(t *testing.T) {
	ready := licence.ReleaseReady()
	out, err := capture(t, "keys", "--release-check")
	switch {
	case ready == nil && err != nil:
		t.Fatalf("a production key is embedded but --release-check refused: %v\n%s", err, out)
	case ready != nil && err == nil:
		t.Fatalf("--release-check exited 0 while the build embeds no production key (%v). "+
			"That is the whole point of the flag.\n%s", ready, out)
	}
	if ready != nil {
		if !strings.Contains(out, "release-ready: NO") {
			t.Errorf("the refusal is not visible in the output:\n%s", out)
		}
		if !strings.Contains(err.Error(), "licence-signing-ceremony") {
			t.Errorf("the refusal does not name the runbook that resolves it: %v", err)
		}
	}
}

func TestKeysRefusesPositionalArguments(t *testing.T) {
	if _, err := capture(t, "keys", "somefile.json"); err == nil {
		t.Fatal("keys accepted a positional argument it does nothing with")
	}
}
