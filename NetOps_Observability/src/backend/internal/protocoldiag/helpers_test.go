package protocoldiag

import (
	"context"
	"testing"
	"time"
)

// ciscoDev is the standard Cisco IOS-XE test device.
var ciscoDev = Device{
	ID:       "dev-1",
	Hostname: "core-01",
	Platform: "Cisco IOS-XE 17.9",
	TenantID: "acme",
}

// stdTarget is the standard command target used across the analyze fixtures.
var stdTarget = Target{
	Interface: "GigabitEthernet0/0",
	Peer:      "10.0.0.2",
	Prefix:    "192.0.2.0/24",
}

// fixedClock returns a monotonically increasing clock so every collected command
// gets a distinct, deterministic timestamp.
func fixedClock() func() time.Time {
	base := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	var n int
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// runnerFor builds a MemCommandRunner mapping each spec's RENDERED command (for
// dev/tgt) to the output supplied by spec id. Specs with no supplied output are
// left unmapped (the runner then returns an empty, successful capture).
func runnerFor(t *testing.T, issue Issue, dev Device, tgt Target, bySpec map[string]string) MemCommandRunner {
	t.Helper()
	m := MemCommandRunner{}
	for _, s := range issue.Bundle() {
		if out, ok := bySpec[s.ID]; ok {
			m[s.Render(dev.Vendor(), tgt)] = out
		}
	}
	return m
}

// collectFor runs Collect for one issue with the given per-spec outputs and
// returns the Collection. It fails the test on any collect error.
func collectFor(t *testing.T, cat *Catalog, dev Device, tgt Target, issueID string, bySpec map[string]string) *Collection {
	t.Helper()
	issue, ok := cat.Issue(issueID)
	if !ok {
		t.Fatalf("unknown issue %q", issueID)
	}
	runner := runnerFor(t, issue, dev, tgt, bySpec)
	col, err := NewCollector(cat, runner, WithClock(fixedClock()))
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	got, err := col.Collect(context.Background(), dev, issueID, tgt)
	if err != nil {
		t.Fatalf("Collect(%s): %v", issueID, err)
	}
	return got
}

// findingIDs returns the fired signature ids of a result.
func findingIDs(r AnalyzeResult) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.SignatureID)
	}
	return out
}

// hasFinding reports whether id is among the fired findings.
func hasFinding(r AnalyzeResult, id string) bool {
	for _, f := range r.Findings {
		if f.SignatureID == id {
			return true
		}
	}
	return false
}
