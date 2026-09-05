package tac

import (
	"strings"
	"testing"
)

// TestClassifyTable is the evidence → class table. Each row is a realistic
// incident's evidence and the class an operator would expect Correlix to name.
func TestClassifyTable(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, tc := range []struct {
		name string
		ev   Evidence
		want string
		// wantClassified false means the honest "we did not classify it" answer.
		wantClassified bool
	}{
		{
			name:           "ospf adjacency from a matched signature",
			ev:             Evidence{Signatures: []string{"ospf-exstart-mtu"}, Alerts: []string{"OSPFAdjacencyDown"}},
			want:           "ospf-adjacency",
			wantClassified: true,
		},
		{
			name:           "bgp session from alert plus skill",
			ev:             Evidence{Alerts: []string{"BGPSessionDown"}, Skills: []string{"bgp-session-down"}},
			want:           "bgp-session",
			wantClassified: true,
		},
		{
			name:           "bgp route missing from the RCA hypothesis",
			ev:             Evidence{Hypotheses: []string{"sig.ent.middle-mile.private-interconnect-missing-prefix"}},
			want:           "bgp-route-missing",
			wantClassified: true,
		},
		{
			name:           "isis adjacency from the fabric hypothesis and its alert",
			ev:             Evidence{Hypotheses: []string{"sig.ent.fabric.isis-adjacency-flap"}, Alerts: []string{"ISISAdjacencyDown"}},
			want:           "isis-adjacency",
			wantClassified: true,
		},
		{
			name:           "optics from the optic alerts",
			ev:             Evidence{Alerts: []string{"OpticRxPowerLow", "OpticTemperatureHigh"}, Skills: []string{"optics-degraded"}},
			want:           "optics",
			wantClassified: true,
		},
		{
			name:           "flapping link beats plain link-flap when OSPF is involved",
			ev:             Evidence{Signatures: []string{"ospf-flap-l1"}, Alerts: []string{"OSPFAdjacencyFlapping", "InterfaceFlapping"}},
			want:           "ospf-flapping-link",
			wantClassified: true,
		},
		{
			name:           "hardware fault from a fan failure",
			ev:             Evidence{Alerts: []string{"FanFailed", "TemperatureHigh"}},
			want:           "hardware-fault",
			wantClassified: true,
		},
		{
			name:           "mlag from a log line alone",
			ev:             Evidence{LogLines: []string{"%VPC-2-PEER_KEEPALIVE_RECV_FAIL: vPC peer-keepalive receive failed"}},
			want:           "mlag-vpc-peer",
			wantClassified: true,
		},
		{
			name:           "config change",
			ev:             Evidence{Alerts: []string{"ConfigChanged"}, LogLines: []string{"%SYS-5-CONFIG_I: Configured from console"}},
			want:           "config-change",
			wantClassified: true,
		},
		{
			name:           "nothing recognised is the generic class, honestly",
			ev:             Evidence{Alerts: []string{"SomeAlertNobodyDeclared"}, LogLines: []string{"nothing to see"}},
			want:           GenericClassID,
			wantClassified: false,
		},
		{
			name:           "empty evidence is the generic class",
			ev:             Evidence{},
			want:           GenericClassID,
			wantClassified: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Classify(tc.ev)
			if got.ClassID != tc.want {
				t.Fatalf("classified as %q (why=%v), want %q", got.ClassID, got.Why, tc.want)
			}
			if got.Classified != tc.wantClassified {
				t.Fatalf("Classified=%v, want %v", got.Classified, tc.wantClassified)
			}
			if tc.wantClassified && len(got.Why) == 0 {
				t.Fatal("a classified result must name the evidence that produced it")
			}
			if !tc.wantClassified && !strings.Contains(got.Note, "did not classify") {
				t.Fatalf("the unclassified note must say so plainly, got %q", got.Note)
			}
		})
	}
}

// TestClassifyIsDeterministic pins the tie-break, so the same evidence never
// produces two different answers on two runs.
func TestClassifyIsDeterministic(t *testing.T) {
	c := mustCatalog(t)
	ev := Evidence{
		Alerts:     []string{"InterfaceFlapping", "InterfaceInputErrors"},
		Hypotheses: []string{"sig.ent.access.local-link-fault"},
	}
	first := c.Classify(ev)
	for i := 0; i < 25; i++ {
		got := c.Classify(ev)
		if got.ClassID != first.ClassID || len(got.Alternatives) != len(first.Alternatives) {
			t.Fatalf("classification is not deterministic: %q then %q", first.ClassID, got.ClassID)
		}
	}
}

// TestClassifyNeverScoresGeneric proves the fallback class cannot be "matched".
func TestClassifyNeverScoresGeneric(t *testing.T) {
	c := mustCatalog(t)
	res := c.Classify(Evidence{Alerts: []string{"BGPSessionDown"}})
	for _, alt := range res.Alternatives {
		if alt.ClassID == GenericClassID {
			t.Fatal("generic appeared as a scored alternative; it is the fallback, not a matcher")
		}
	}
}

// TestClassifyEvidenceIsCountedOnce proves a repeated reference does not inflate
// a class's score.
func TestClassifyEvidenceIsCountedOnce(t *testing.T) {
	c := mustCatalog(t)
	one := c.Classify(Evidence{Alerts: []string{"BGPSessionDown"}})
	many := c.Classify(Evidence{Alerts: []string{"BGPSessionDown", "BGPSessionDown", "BGPSessionDown"}})
	if len(one.Why) != len(many.Why) {
		t.Fatalf("a repeated alert changed the score: %d vs %d reasons", len(one.Why), len(many.Why))
	}
}

// TestClassifyLogScanIsBounded proves a flood of log lines cannot make
// classification unbounded work.
func TestClassifyLogScanIsBounded(t *testing.T) {
	c := mustCatalog(t)
	lines := make([]string, 50_000)
	for i := range lines {
		lines[i] = "a perfectly ordinary log line with nothing in it"
	}
	lines[maxClassifyLogLines+10] = "%SYS-5-CONFIG_I: Configured from console"
	res := c.Classify(Evidence{LogLines: lines})
	if res.Classified {
		t.Fatal("a log line beyond the scan cap was read; the scan is not bounded")
	}
}
