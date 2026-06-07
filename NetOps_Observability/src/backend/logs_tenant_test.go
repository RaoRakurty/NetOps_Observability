package main

import (
	"reflect"
	"testing"
)

// TestIndexTenantSeg pins the tenant→index-segment sanitization. It MUST stay in
// lockstep with the VRL in deployment/docker/vector-router/vector.yaml, or reads
// would name indices ingest never wrote.
func TestIndexTenantSeg(t *testing.T) {
	cases := map[string]string{
		"":           "untagged",
		"  ":         "untagged",
		"acme":       "acme",
		"Acme":       "acme",
		"Acme Corp":  "acme-corp",
		"a.b/c:d":    "a-b-c-d",
		"tenant_1-2": "tenant_1-2", // underscore + dash preserved
	}
	for in, want := range cases {
		if got := indexTenantSeg(in); got != want {
			t.Errorf("indexTenantSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTenantIndexPattern verifies a scoped tenant only ever names its own + the
// untagged indices, while the platform owner names everything.
func TestTenantIndexPattern(t *testing.T) {
	if got := tenantIndexPattern("applogs", "acme", true); got != "netops-applogs-*" {
		t.Errorf("platform applogs = %q", got)
	}
	if got := tenantIndexPattern("applogs", "acme", false); got != "netops-applogs-acme-*,netops-applogs-untagged-*" {
		t.Errorf("scoped applogs = %q", got)
	}
	if got := tenantIndexPattern("syslog", "acme", false); got != "netops-syslog-acme-*,netops-syslog-untagged-*" {
		t.Errorf("scoped syslog = %q", got)
	}
	if got := tenantIndexPattern("flows", "globex", false); got != "netops-flows-globex-*,netops-flows-untagged-*" {
		t.Errorf("scoped flows = %q", got)
	}
	// A scoped tenant's pattern must never name another tenant's index.
	if pat := tenantIndexPattern("syslog", "acme", false); containsSub(pat, "globex") {
		t.Errorf("acme pattern leaked another tenant: %q", pat)
	}
}

func TestTenantCatPattern(t *testing.T) {
	if got := tenantCatPattern("acme", true); got != "netops-*" {
		t.Errorf("platform cat = %q", got)
	}
	got := tenantCatPattern("acme", false)
	// Device-telemetry signals (syslog, snmp traps, flows) are tenant-visible:
	// the caller's own + the shared untagged indices.
	for _, want := range []string{
		"netops-syslog-acme-*", "netops-snmptrap-acme-*", "netops-flows-acme-*",
		"netops-syslog-untagged-*", "netops-snmptrap-untagged-*", "netops-flows-untagged-*",
	} {
		if !containsSub(got, want) {
			t.Errorf("scoped cat %q missing %q", got, want)
		}
	}
	// App logs are the platform's own logs — a scoped tenant doesn't even
	// enumerate their index names.
	if containsSub(got, "applogs") {
		t.Errorf("scoped cat must not expose app-log indices: %q", got)
	}
	if containsSub(got, "globex") {
		t.Errorf("scoped cat leaked another tenant: %q", got)
	}
}

// TestOSTenantFilter checks the read clause: nil for the platform owner; for a
// scoped caller, "my tenant_id OR (untagged AND my device)".
func TestOSTenantFilter(t *testing.T) {
	if f := osTenantFilter("acme", true, nil, nil); f != nil {
		t.Fatalf("platform owner must get no filter, got %v", f)
	}
	f := osTenantFilter("acme", false, []string{"leaf1"}, []string{"10.0.0.1"})
	b, ok := f["bool"].(map[string]any)
	if !ok {
		t.Fatalf("expected bool clause, got %T", f["bool"])
	}
	should, ok := b["should"].([]any)
	if !ok || len(should) != 2 {
		t.Fatalf("expected 2 should-branches (tagged + untagged), got %v", b["should"])
	}
	// First branch is the exact own-tenant match.
	first, _ := should[0].(map[string]any)
	term, _ := first["term"].(map[string]any)
	if !reflect.DeepEqual(term, map[string]any{"tenant_id": "acme"}) {
		t.Errorf("first branch should be term tenant_id=acme, got %v", first)
	}
	if b["minimum_should_match"] != 1 {
		t.Errorf("minimum_should_match must be 1, got %v", b["minimum_should_match"])
	}
}

// TestOSTenantFilterNoDevices: a scoped tenant with no visible devices still sees
// its own tagged docs, but the untagged branch matches nothing (match_none).
func TestOSTenantFilterNoDevices(t *testing.T) {
	f := osTenantFilter("acme", false, nil, nil)
	b := f["bool"].(map[string]any)
	should := b["should"].([]any)
	untagged := should[1].(map[string]any)["bool"].(map[string]any)["must"].([]any)
	devBool := untagged[1].(map[string]any)["bool"].(map[string]any)["should"].([]any)
	if len(devBool) != 1 {
		t.Fatalf("expected single device branch, got %v", devBool)
	}
	if _, isNone := devBool[0].(map[string]any)["match_none"]; !isNone {
		t.Errorf("no-device untagged branch must be match_none, got %v", devBool[0])
	}
}

func containsSub(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
