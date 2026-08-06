package secobs

import (
	"strings"
	"testing"
	"time"
)

func fixedNow() time.Time { return time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC) }

func testInventory() *Inventory {
	return &Inventory{SchemaVersion: 1, Edges: []Edge{
		{ID: "api-postgres", Source: "api", Destination: "postgres", Channel: "store", Protocol: "postgres", Port: 5432,
			TrustDomain: "workload", Current: EdgeSide{Transport: "plaintext"},
			SecurityProfile: &EdgeSide{Transport: "tls-verify-full"}, Target: EdgeSide{Transport: "tls-verify-full"}},
		{ID: "api-kafka", Source: "api", Destination: "kafka", Channel: "bus", Protocol: "kafka", Port: 9094,
			TrustDomain: "workload", Current: EdgeSide{Transport: "plaintext"},
			SecurityProfile: &EdgeSide{Transport: "mtls"}, Target: EdgeSide{Transport: "mtls"}},
		{ID: "vmauth-victoria", Source: "vmauth", Destination: "victoria", Channel: "store", Protocol: "http", Port: 8428,
			TrustDomain: "workload", Current: EdgeSide{Transport: "plaintext"}, Target: EdgeSide{Transport: "plaintext-DECLARED"},
			Exception: &Exception{Owner: "platform-eng", Accepted: "2026-08-01", Reason: "vmauth proxy hop"}},
		{ID: "device-flows", Source: "device", Destination: "goflow2", Channel: "flow", Protocol: "udp", Port: 6343,
			TrustDomain: "device", Current: EdgeSide{Transport: "plaintext"}, Target: EdgeSide{Transport: "plaintext-DECLARED"},
			Exception: &Exception{Owner: "platform-eng", Accepted: "2026-08-01", Reason: "UDP flow protocols cannot be encrypted"}},
	}}
}

func TestBuildPostureDriftDirections(t *testing.T) {
	inv := testInventory()
	probes := map[string]ProbeObservation{
		// Declared TLS, no cert on the wire → the bad drift.
		"postgres:5432": {OK: false, CheckedAt: fixedNow()},
		// Declared mTLS, cert served and future-dated → no drift.
		"kafka:9094": {OK: true, NotAfter: fixedNow().Add(72 * time.Hour), CheckedAt: fixedNow()},
		// Declared plaintext, cert observed → the good drift (declaration lags).
		"victoria:8428": {OK: true, NotAfter: fixedNow().Add(72 * time.Hour), CheckedAt: fixedNow()},
	}
	rows := BuildPosture(inv, probes, fixedNow)
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	byID := map[string]PostureRow{}
	for _, r := range rows {
		byID[r.Edge] = r
	}
	if d := byID["api-postgres"].Drift; !strings.Contains(d, "no certificate observed") {
		t.Errorf("api-postgres drift = %q, want no-certificate-observed", d)
	}
	if d := byID["api-kafka"].Drift; d != "" {
		t.Errorf("api-kafka drift = %q, want none", d)
	}
	if d := byID["vmauth-victoria"].Drift; !strings.Contains(d, "certificate observed on an edge declared") {
		t.Errorf("vmauth-victoria drift = %q, want declaration-lags note", d)
	}
	// No probe watches the flow lane → Observed nil, no drift claim.
	if r := byID["device-flows"]; r.Observed != nil || r.Drift != "" {
		t.Errorf("device-flows must be unobserved with no drift, got %+v", r)
	}
	// Exception ageing: accepted 2026-08-01, now 2026-08-06 → 5 days.
	if got := byID["vmauth-victoria"].AgeDays; got != 5 {
		t.Errorf("exception age = %d days, want 5", got)
	}
}

func TestBuildPostureExpiredCert(t *testing.T) {
	inv := testInventory()
	probes := map[string]ProbeObservation{
		"kafka:9094": {OK: true, NotAfter: fixedNow().Add(-time.Hour), CheckedAt: fixedNow()},
	}
	rows := BuildPosture(inv, probes, fixedNow)
	for _, r := range rows {
		if r.Edge == "api-kafka" && !strings.Contains(r.Drift, "EXPIRED") {
			t.Fatalf("expired served cert must surface as drift, got %q", r.Drift)
		}
	}
}

func TestBuildPostureNilInventory(t *testing.T) {
	if rows := BuildPosture(nil, nil, fixedNow); rows != nil {
		t.Fatalf("nil inventory must yield nil rows, got %d", len(rows))
	}
}

func TestDeviceLaneRows(t *testing.T) {
	rows := BuildPosture(testInventory(), nil, fixedNow)
	lanes := DeviceLaneRows(rows)
	if len(lanes) != 1 || lanes[0].Edge != "device-flows" {
		t.Fatalf("device lanes = %+v, want exactly device-flows", lanes)
	}
}

func TestPostureTableRendering(t *testing.T) {
	inv := testInventory()
	probes := map[string]ProbeObservation{
		"kafka:9094": {OK: true, NotAfter: fixedNow().Add(48 * time.Hour), CheckedAt: fixedNow()},
	}
	rows := BuildPosture(inv, probes, fixedNow)
	for i := range rows {
		if rows[i].Edge == "api-kafka" {
			rows[i].Identity = "spiffe://netops/ns/default/sa/kafka"
		}
	}
	header, cells := PostureTable(rows, fixedNow)
	if len(header) != 8 {
		t.Fatalf("header = %v", header)
	}
	if len(cells) != len(rows) {
		t.Fatalf("cells = %d, want %d", len(cells), len(rows))
	}
	joined := ""
	for _, row := range cells {
		joined += strings.Join(row, "|") + "\n"
	}
	for _, want := range []string{
		"spiffe://netops/ns/default/sa/kafka", // identity rendered
		"2.0d",                                // expiry in days
		"not probed",                          // unobserved edges say so
		"owner platform-eng",                  // exception verbalized with owner
		"5d ago",                              // and its age
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("table missing %q:\n%s", want, joined)
		}
	}
}

func TestTierExpectsTLS(t *testing.T) {
	for tier, want := range map[string]bool{
		"tls": true, "mtls": true, "tls-via-vmauth": true, "tls-verify-full": true,
		"mtls-tls": true, "plaintext": false, "plaintext-DECLARED": false,
		"plaintext-authenticated": false, "protocol_native": false, "": false,
	} {
		if got := tierExpectsTLS(tier); got != want {
			t.Errorf("tierExpectsTLS(%q) = %v, want %v", tier, got, want)
		}
	}
}
