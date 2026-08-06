package secobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// repoInventoryPath is the checked-in inventory, reachable from this package
// the same way workloadid_test reaches the compose file.
func repoInventoryPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "..", "docs", "security", "transport-inventory.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("checked-in transport inventory not found at %s: %v", p, err)
	}
	return p
}

func TestVocabularyIsValid(t *testing.T) {
	if err := ValidateVocabulary(); err != nil {
		t.Fatal(err)
	}
}

func TestVocabularyEmittedFamiliesAreWritten(t *testing.T) {
	// Every StatusEmitted netops_sec_* family must appear in the writer's
	// output — a vocabulary row that claims "emitted" while nothing emits it
	// is exactly the silent mis-fire SEC-020 exists to prevent.
	inv, err := LoadInventory(repoInventoryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	NewMetrics(inv, 1, 2, 3, nil).Write(&b)
	out := b.String()
	for _, f := range Vocabulary {
		if f.Status != StatusEmitted || !strings.HasPrefix(f.Name, "netops_sec_") {
			continue
		}
		if !strings.Contains(out, f.Name+"{") {
			t.Errorf("vocabulary family %s is StatusEmitted but absent from Metrics.Write output", f.Name)
		}
		if !strings.Contains(out, "# TYPE "+f.Name+" "+f.Type) {
			t.Errorf("family %s missing TYPE %s declaration", f.Name, f.Type)
		}
	}
}

func TestLoadInventoryRepoFile(t *testing.T) {
	inv, err := LoadInventory(repoInventoryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Edges) < 30 {
		t.Fatalf("inventory has %d edges — parser drift or a gutted file", len(inv.Edges))
	}
	// The declared-exception mechanism only means something if the known
	// permanent-plaintext lanes actually carry exceptions.
	exc := inv.Exceptions()
	ids := make(map[string]bool, len(exc))
	for _, e := range exc {
		ids[e.ID] = true
	}
	for _, want := range []string{"device-goflow2", "vmauth-victoria"} {
		if !ids[want] {
			t.Errorf("edge %s must carry a declared exception", want)
		}
	}
	// Every plaintext-DECLARED target must carry an exception: accepted
	// plaintext without an owner and a date is a rubber stamp (HLD §11).
	for _, e := range inv.Edges {
		if e.Target.Transport == "plaintext-DECLARED" && e.Exception == nil {
			t.Errorf("edge %s declares a plaintext end state but has no exception object", e.ID)
		}
	}
}

func TestLoadInventoryRejectsBadFiles(t *testing.T) {
	cases := map[string]string{
		"missing":       "", // path that does not exist
		"not-json":      `hello: world:`,
		"no-edges":      `{"schema_version":1,"edges":[]}`,
		"bad-version":   `{"schema_version":2,"edges":[{"id":"a","source":"s","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"}}]}`,
		"dup-id":        `{"schema_version":1,"edges":[{"id":"a","source":"s","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"}},{"id":"a","source":"s","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"}}]}`,
		"exc-no-owner":  `{"schema_version":1,"edges":[{"id":"a","source":"s","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"},"exception":{"accepted":"2026-01-01","reason":"r"}}]}`,
		"exc-bad-date":  `{"schema_version":1,"edges":[{"id":"a","source":"s","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"},"exception":{"owner":"o","accepted":"not-a-date","reason":"r"}}]}`,
		"missing-field": `{"schema_version":1,"edges":[{"id":"a","source":"","destination":"d","channel":"api","current":{"transport":"tls"},"target":{"transport":"tls"}}]}`,
	}
	dir := t.TempDir()
	for name, content := range cases {
		path := filepath.Join(dir, name+".json")
		if name != "missing" {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := LoadInventory(path); err == nil {
			t.Errorf("case %s: expected error, got nil", name)
		}
	}
}

func TestDeclaredTierFallsBackToCurrent(t *testing.T) {
	e := Edge{Current: EdgeSide{Transport: "plaintext"}}
	if got := e.DeclaredTier(); got != "plaintext" {
		t.Fatalf("no security_profile: DeclaredTier = %q, want plaintext", got)
	}
	e.SecurityProfile = &EdgeSide{Transport: "mtls"}
	if got := e.DeclaredTier(); got != "mtls" {
		t.Fatalf("with security_profile: DeclaredTier = %q, want mtls", got)
	}
}

func TestExceptionAgeEmission(t *testing.T) {
	inv := &Inventory{SchemaVersion: 1, Edges: []Edge{
		{ID: "lane-a", Source: "s", Destination: "d", Channel: "flow",
			Current: EdgeSide{Transport: "plaintext"}, Target: EdgeSide{Transport: "plaintext-DECLARED"},
			Exception: &Exception{Owner: "o", Accepted: "2026-08-01", Reason: "r"}},
	}}
	now := func() time.Time { return time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC) }
	var b strings.Builder
	NewMetrics(inv, 0, 0, 0, now).Write(&b)
	want := `netops_sec_exception_age_seconds{edge="lane-a"} 432000`
	if !strings.Contains(b.String(), want) {
		t.Fatalf("expected %q in output:\n%s", want, b.String())
	}
}

func TestNilInventoryEmitsPostureOnly(t *testing.T) {
	// A failed inventory load must not fake zeros: only the validator counts
	// (which do not depend on the inventory) appear.
	var b strings.Builder
	NewMetrics(nil, 5, 0, 0, nil).Write(&b)
	out := b.String()
	if !strings.Contains(out, `netops_sec_posture_findings{severity="fatal"} 5`) {
		t.Fatalf("posture findings missing:\n%s", out)
	}
	if strings.Contains(out, "netops_sec_declared_edges") || strings.Contains(out, "netops_sec_exception_age_seconds") {
		t.Fatalf("inventory-derived families must be absent when the inventory failed to load:\n%s", out)
	}
}

// TestMetricLabelRedaction pins CLAUDE.md §8: label VALUES come from the
// checked-in inventory (edge ids, tier names) and fixed enums — never from the
// environment. The strongest mechanical check available: no emitted label
// value may equal the value of any environment variable that looks like a
// secret.
func TestMetricLabelRedaction(t *testing.T) {
	inv, err := LoadInventory(repoInventoryPath(t))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	NewMetrics(inv, 1, 1, 1, nil).Write(&b)
	out := b.String()
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || v == "" || len(v) < 6 {
			continue
		}
		lk := strings.ToLower(k)
		if strings.Contains(lk, "secret") || strings.Contains(lk, "password") ||
			strings.Contains(lk, "token") || strings.Contains(lk, "key") {
			if strings.Contains(out, v) {
				t.Fatalf("metric output contains the value of environment secret %s", k)
			}
		}
	}
	// And audit event-type constants are a closed enum of identifier-shaped
	// strings.
	for _, s := range SecEventTypes {
		if !metricNameRe.MatchString(s) {
			t.Errorf("sec_event type %q is not identifier-shaped", s)
		}
	}
}
