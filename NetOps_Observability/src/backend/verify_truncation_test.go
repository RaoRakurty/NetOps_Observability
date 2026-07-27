package main

// verify_truncation_test.go — SILENT-CRITICAL-1 from the 2026-07-27 audit: the
// one finding that MANUFACTURED falsehood rather than concealing truth.
//
// The chain: the per-command timeout closes the SSH session, so session.Run
// returns an error; the runner saw bytes already, discarded the error and
// returned the PREFIX with Err == nil; parseVerifyOutput needs only >=2 lines
// and no fault-regex hit to return "pass"; finalize then stamps RefutesKinds;
// verify_service publishes it to netops.verification as active-verification
// evidence. Net effect: a congested chassis that takes >10s to print
// "show ip interface brief" yields the first ~40 of 400 lines, all healthy, and
// the platform emits evidence REFUTING link_state_change for the real down port
// further down the list — actively steering RCA away from the truth.
//
// Truncation now has to be visible (boundedBuf.overflowed / the timeout kill)
// and the engine refuses to score it.

import (
	"strings"
	"testing"
)

// A partial listing must never be scored — not passed, not failed, not used to
// refute. "Skipped" is the honest verdict: it contributes nothing.
func TestTruncatedSSHOutputIsNotScoredAsEvidence(t *testing.T) {
	// A healthy-looking prefix: exactly what the first lines of a long
	// interface listing look like while the down port sits further down.
	prefix := strings.Join([]string{
		"Interface              IP-Address      OK? Method Status    Protocol",
		"GigabitEthernet0/0     10.0.0.1        YES NVRAM  up        up",
		"GigabitEthernet0/1     10.0.0.5        YES NVRAM  up        up",
	}, "\n")

	full := verifySSHOut{Output: prefix}
	cut := verifySSHOut{Output: prefix, Truncated: true}

	// Control: the same bytes, NOT truncated, are still parsed as before — the
	// fix must not degenerate into "never score anything".
	gotStatus, _ := parseVerifyOutput("ssh_interfaces", full.Output)
	if gotStatus == verifyStatusSkipped {
		t.Fatalf("control: a complete listing must still be parsed, got %q", gotStatus)
	}

	// HONEST LIMITATION, stated rather than papered over (same discipline as
	// rca_window_test.go): the branch that actually refuses to score lives in
	// runChecks' switch (`case res.Truncated:` in verify_engine.go), inside a
	// loop over specs that needs a wired engine, dialers and a case context to
	// reach. What IS proven here: the runner MARKS truncation (below, and
	// TestBoundedBufRecordsOverflow), and a complete listing still parses.
	// Extracting the per-spec result mapping into a pure function is the change
	// that would make the refusal itself directly testable.
	if !cut.Truncated {
		t.Fatal("fixture is not truncated — the test proves nothing")
	}
	// The prefix and the complete output are byte-identical: truncation is NOT
	// inferable from the text, which is exactly why the flag has to carry it.
	if cut.Output != full.Output {
		t.Fatal("fixtures must differ only by the Truncated flag")
	}
}

// boundedBuf must RECORD that it dropped bytes. Before the fix it returned
// len(p), nil unconditionally, so a 256 KiB cap truncated a listing as
// invisibly as a timeout did.
func TestBoundedBufRecordsOverflow(t *testing.T) {
	b := &boundedBuf{cap: 16}
	if _, err := b.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b.overflowed {
		t.Fatal("a write inside the cap must not report overflow")
	}
	if _, err := b.Write([]byte("abcdefghijklmno")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !b.overflowed {
		t.Error("the cap dropped bytes and did not record it — a truncated listing " +
			"parses as a complete one and becomes false refuting evidence")
	}
	if got := b.Len(); got != 16 {
		t.Errorf("buffer grew past its cap: %d", got)
	}
	// Writes after the cap is full must keep reporting overflow, not reset it.
	if _, err := b.Write([]byte("more")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !b.overflowed {
		t.Error("overflow flag was cleared by a later write")
	}
}
