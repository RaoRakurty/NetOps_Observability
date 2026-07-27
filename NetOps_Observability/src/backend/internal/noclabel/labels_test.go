package noclabel

import (
	"reflect"
	"testing"
)

func TestKind(t *testing.T) {
	if got := Kind("bgp_adjacency_change"); got != "BGP neighbor change" {
		t.Errorf("mapped kind = %q", got)
	}
	// a *_clear variant maps like its base kind
	if got := Kind("probe_loss_clear"); got != "Packet loss" {
		t.Errorf("clear-suffix kind = %q", got)
	}
	// unmapped kind humanizes instead of leaking the raw token
	if got := Kind("qos_drops"); got != "Qos drops" {
		t.Errorf("fallback = %q", got)
	}
	if got := Kind(""); got != "Event" {
		t.Errorf("empty kind = %q", got)
	}
}

func TestProblemDisplayID(t *testing.T) {
	if got := ProblemDisplayID("5564d1ab-0000-4000-8000-000000000000"); got != "P-5564D1" {
		t.Errorf("uuid → %q", got)
	}
	// idempotent: an already-friendly handle passes through
	if got := ProblemDisplayID("P-5564D1"); got != "P-5564D1" {
		t.Errorf("friendly id rewritten to %q", got)
	}
	if got := ProblemDisplayID("abc"); got != "abc" {
		t.Errorf("short non-uuid rewritten to %q", got)
	}
	if got := ProblemDisplayID(""); got != "" {
		t.Errorf("empty → %q", got)
	}
}

func TestEntity(t *testing.T) {
	cases := map[string]string{
		"device:leaf1":               "leaf1",
		"192.0.2.120:established(6)": "Monitored endpoint",
		"host:demo-target":           "Internal / test target",
		"leaf1":                      "leaf1",
	}
	for in, want := range cases {
		if got := Entity(in); got != want {
			t.Errorf("Entity(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Entities([]string{"a:b", "a:established(6)", "leaf1"}); !reflect.DeepEqual(got, []string{"a", "leaf1"}) {
		t.Errorf("Entities dedupe = %v", got)
	}
}

func TestSignatureTitleCascadeOrder(t *testing.T) {
	// explicit map wins
	if got := SignatureTitle("sig.ent.middle-mile.dia-egress-latency"); got != "ISP / DIA egress latency" {
		t.Errorf("mapped = %q", got)
	}
	// app/SaaS before every network rung (owner directive 2026-07-12)
	if got := SignatureTitle("sig.ent.app.someting-new-with-bgp"); got != "Application / service experience change" {
		t.Errorf("app-lane = %q", got)
	}
	// middle-mile BEFORE the tunnel group: an underlay signature mentioning
	// ipsec is a transport fault, not an SD-WAN one (truthfulness epic D1a).
	if got := SignatureTitle("sig.ent.middle-mile.ipsec-new-variant"); got != "WAN / provider path change" {
		t.Errorf("middle-mile ipsec = %q", got)
	}
	// honest last resort: never assert "network change" without evidence
	if got := SignatureTitle("sig.ent.mystery.unmapped"); got != "Anomaly observed — cause undetermined" {
		t.Errorf("last resort = %q", got)
	}
	if got := SignatureTitle(""); got != "" {
		t.Errorf("empty = %q", got)
	}
}

func TestHumanizeMissing(t *testing.T) {
	in := []string{"sig.ent.middle-mile.dia-egress-latency: single modality"}
	want := []string{"ISP / DIA egress latency: single modality"}
	if got := HumanizeMissing(in); !reflect.DeepEqual(got, want) {
		t.Errorf("HumanizeMissing = %v", got)
	}
	if got := HumanizeMissing(nil); got != nil {
		t.Errorf("nil in, %v out", got)
	}
}

func TestProblemTitle(t *testing.T) {
	if got := ProblemTitle("sig.ent.sdwan.brownout", "x"); got != "SD-WAN path brownout" {
		t.Errorf("sig title = %q", got)
	}
	if got := ProblemTitle("Fiber cut on span 4", "x"); got != "Fiber cut on span 4" {
		t.Errorf("human hypothesis rewritten: %q", got)
	}
	if got := ProblemTitle("undetermined", "x"); got != "Low-evidence correlation" {
		t.Errorf("undetermined = %q", got)
	}
}
