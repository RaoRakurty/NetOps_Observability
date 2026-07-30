package backend

import (
	"reflect"
	"testing"

	"netops/backend/internal/oslog"
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
		if got := oslog.IndexTenantSeg(in); got != want {
			t.Errorf("oslog.IndexTenantSeg(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTenantIndexPattern verifies a scoped tenant only ever names its own + the
// untagged indices, while the platform owner names everything.
func TestTenantIndexPattern(t *testing.T) {
	if got := oslog.TenantIndexPattern("applogs", "acme", true); got != "netops-applogs-*" {
		t.Errorf("platform applogs = %q", got)
	}
	if got := oslog.TenantIndexPattern("applogs", "acme", false); got != "netops-applogs-acme-*,netops-applogs-untagged-*" {
		t.Errorf("scoped applogs = %q", got)
	}
	if got := oslog.TenantIndexPattern("syslog", "acme", false); got != "netops-syslog-acme-*,netops-syslog-untagged-*" {
		t.Errorf("scoped syslog = %q", got)
	}
	if got := oslog.TenantIndexPattern("flows", "globex", false); got != "netops-flows-globex-*,netops-flows-untagged-*" {
		t.Errorf("scoped flows = %q", got)
	}
	// A scoped tenant's pattern must never name another tenant's index.
	if pat := oslog.TenantIndexPattern("syslog", "acme", false); containsSub(pat, "globex") {
		t.Errorf("acme pattern leaked another tenant: %q", pat)
	}
}

func TestTenantCatPattern(t *testing.T) {
	if got := oslog.TenantCatPattern("acme", true); got != "netops-*" {
		t.Errorf("platform cat = %q", got)
	}
	got := oslog.TenantCatPattern("acme", false)
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
	if f := oslog.TenantFilter("acme", true, nil, nil); f != nil {
		t.Fatalf("platform owner must get no filter, got %v", f)
	}
	f := oslog.TenantFilter("acme", false, []string{"leaf1"}, []string{"10.0.0.1"})
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
	f := oslog.TenantFilter("acme", false, nil, nil)
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

// TestTenantIndexPattern_AllExcludesAppLogs is the regression guard for the
// platform↔tenant boundary: an "all"/default search must NEVER touch the
// platform's own app-log indices — for ANY caller, platform owner included (no
// mixing stack internals into device logs). It must, however, still cover all
// device-telemetry LOG signals. If a future change reintroduces applogs into
// "all", or drops a log signal, this fails. Flows are intentionally NOT in "all"
// (5-tuple records, no message/level, ~1000:1 volume drowns real logs incl.
// firewall/fw_logs) — reachable only via signal="flows".
func TestTenantIndexPattern_AllExcludesAppLogs(t *testing.T) {
	for _, sig := range []string{"", "all"} {
		for _, cross := range []bool{true, false} {
			pat := oslog.TenantIndexPattern(sig, "acme", cross)
			if containsSub(pat, "applogs") {
				t.Errorf("oslog.TenantIndexPattern(%q, acme, cross=%v) LEAKED app logs into 'all': %q", sig, cross, pat)
			}
			if containsSub(pat, "netops-flows") {
				t.Errorf("oslog.TenantIndexPattern(%q, acme, cross=%v) must NOT include flows in 'all' (drowns real logs): %q", sig, cross, pat)
			}
			for _, want := range []string{"netops-syslog", "netops-snmptrap"} {
				if !containsSub(pat, want) {
					t.Errorf("oslog.TenantIndexPattern(%q, acme, cross=%v) missing log signal %q: %q", sig, cross, want, pat)
				}
			}
		}
	}
	// A scoped "all" must never name another tenant's indices.
	if pat := oslog.TenantIndexPattern("", "acme", false); containsSub(pat, "globex") {
		t.Errorf("scoped 'all' leaked another tenant: %q", pat)
	}
}

// TestAppLogPatternAllowed pins the defense-in-depth guardrail: a non-platform-
// owner is denied ANY resolved index pattern that references the platform's
// app-log indices, regardless of how the pattern was built — so a regression in
// signal/index logic still cannot leak platform internals to a tenant.
func TestAppLogPatternAllowed(t *testing.T) {
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}
	tenantAdmin := jwtClaims{Sub: "a", Role: RoleSuperAdmin, Tenant: "acme"} // tenant super-admin ≠ platform owner
	operator := jwtClaims{Sub: "o", Role: RoleOperator, Tenant: "acme"}

	if !oslog.AppLogPatternAllowed("netops-applogs-*", isPlatformOwner(owner)) {
		t.Error("platform owner must be allowed to read app-log indices")
	}
	for _, c := range []jwtClaims{tenantAdmin, operator} {
		if oslog.AppLogPatternAllowed("netops-applogs-untagged-*", isPlatformOwner(c)) {
			t.Errorf("non-owner %s must be DENIED an app-log pattern (leak guard)", c.Sub)
		}
		if !oslog.AppLogPatternAllowed("netops-syslog-acme-*,netops-syslog-untagged-*", isPlatformOwner(c)) {
			t.Errorf("non-owner %s must be allowed device-telemetry patterns", c.Sub)
		}
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
