package tac

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// plantedSecret is the string that must never survive into a bundle. It is
// deliberately shaped like the credentials `show run`-adjacent output really
// carries.
const plantedSecret = "Tr0ub4dor&3xyz"

func fixedClock() func() time.Time {
	t0 := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t0 }
}

func buildFixtureCapture(t *testing.T) (*Plan, *Capture) {
	t.Helper()
	cat := mustCatalog(t)
	p, err := cat.Plan("bgp-session", iosxeDevice(), PlanOptions{Target: Target{Peer: "192.0.2.1"}})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	p.IncidentID = "inc-1"
	f := newFake()
	for _, s := range p.Steps {
		f.out[s.Command] = "line one\nline two\n"
	}
	// Plant a secret in one output and in one error string.
	f.out[p.Steps[0].Command] = "hostname core1\nusername admin password 7 " + plantedSecret + "\n"
	f.fail[p.Steps[1].Command] = errors.New("device said: snmp-server community " + plantedSecret + " ro")
	capt, err := testCollector(t, f, WithClock(fixedClock())).Collect(context.Background(), p, nil, nil)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return p, capt
}

func fixtureBundleInput(t *testing.T) BundleInput {
	t.Helper()
	cat := mustCatalog(t)
	p, capt := buildFixtureCapture(t)
	cls := cat.Classify(Evidence{Alerts: []string{"BGPSessionDown"}, Skills: []string{"bgp-session-down"}})
	return BundleInput{
		TenantID: "t1", IncidentID: "inc-1", IncidentRef: "INC-3FA2C1",
		Title:       "BGP session to 192.0.2.1 is down",
		WindowStart: time.Date(2026, 9, 5, 11, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 9, 5, 11, 45, 0, 0, time.UTC),
		Actor:       "operator@example.test",
		Class:       cls, Plan: p, Capture: capt,
		Alerts: []AlertFact{{Name: "BGPSessionDown", Severity: "critical", Device: "core1",
			Summary: "peer 192.0.2.1 idle; snmp-server community " + plantedSecret + " ro"}},
		Hypotheses: []HypothesisFact{{TemplateID: "sig.ent.middle-mile.private-interconnect-bgp-down",
			Title: "Private interconnect BGP down", Confidence: "0.71", State: "suspected"}},
		Logs: []LogLine{{At: time.Date(2026, 9, 5, 11, 2, 0, 0, time.UTC), Device: "core1", Severity: "5",
			Message: "%BGP-5-ADJCHANGE: neighbor 192.0.2.1 Down; enable secret 5 " + plantedSecret}},
		Findings:    []FindingFact{{ID: "F-1", Title: "Telnet enabled", Severity: "high", Device: "core1"}},
		Correlation: map[string]any{"correlation_id": "abc", "verdict_tier": "suspected"},
		DeviceFacts: map[string]string{"serial": "FTX1234ABCD", "note": "enable password " + plantedSecret},
	}
}

func unzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("zip: %v", err)
	}
	out := map[string][]byte{}
	for _, f := range zr.File {
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("open %s: %v", f.Name, oerr)
		}
		b, rerr := io.ReadAll(rc)
		_ = rc.Close()
		if rerr != nil {
			t.Fatalf("read %s: %v", f.Name, rerr)
		}
		out[f.Name] = b
	}
	return out
}

// TestBundleLayout pins the file set a TAC engineer will look for.
func TestBundleLayout(t *testing.T) {
	b, err := BuildBundle(context.Background(), fixtureBundleInput(t), nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	files := unzip(t, b.Zip)
	for _, want := range []string{
		"MANIFEST.json", "PROBLEM_STATEMENT.md", "SHA256SUMS",
		"evidence/index.json", "evidence/alerts.json", "evidence/hypotheses.json",
		"evidence/findings.json", "evidence/logs.txt", "evidence/correlation.json",
		"topology.json", "device.json",
	} {
		if _, ok := files[want]; !ok {
			t.Errorf("bundle is missing %s", want)
		}
	}
	var outputs int
	for name := range files {
		if strings.HasPrefix(name, "outputs/") {
			outputs++
		}
	}
	if outputs == 0 {
		t.Fatal("no command outputs in the bundle")
	}
	if !strings.HasPrefix(b.Name, "correlix-tac-") || !strings.HasSuffix(b.Name, ".zip") {
		t.Fatalf("bundle name %q", b.Name)
	}
	if strings.Contains(b.Name, "t1") {
		t.Fatal("the bundle filename must not carry the tenant id — the file leaves the operator's hands")
	}
}

// TestBundleRedactsEverySection is the planted-secret test: the secret is put in
// a command output, a command error, an alert summary, a log line and a device
// fact, and must appear in NONE of them.
func TestBundleRedactsEverySection(t *testing.T) {
	b, err := BuildBundle(context.Background(), fixtureBundleInput(t), nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if bytes.Contains(b.Zip, []byte(plantedSecret)) {
		// Locate it precisely so a failure is actionable.
		for name, data := range unzip(t, b.Zip) {
			if bytes.Contains(data, []byte(plantedSecret)) {
				t.Errorf("the planted secret survived into %s", name)
			}
		}
		t.Fatal("a secret reached the bundle")
	}
	files := unzip(t, b.Zip)
	if !bytes.Contains(files["evidence/logs.txt"], []byte("[REDACTED]")) {
		t.Fatal("the log excerpt was not redacted through the shared pass")
	}
	if !bytes.Contains(files["evidence/alerts.json"], []byte("[REDACTED]")) {
		t.Fatal("the alert summary was not redacted")
	}
	if !bytes.Contains(files["device.json"], []byte("[REDACTED]")) {
		t.Fatal("the device facts were not redacted")
	}
}

// TestBundleManifestTellsTheTruth pins the gap fields.
func TestBundleManifestTellsTheTruth(t *testing.T) {
	in := fixtureBundleInput(t)
	b, err := BuildBundle(context.Background(), in, nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(unzip(t, b.Zip)["MANIFEST.json"], &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Format != "correlix-tac-bundle/1" || m.EngineVersion != Version {
		t.Fatalf("manifest identity: %+v", m.Format)
	}
	if m.CatalogVersion == "" {
		t.Fatal("the manifest must stamp the taxonomy version it was built under")
	}
	if len(m.Failed) != 1 {
		t.Fatalf("the failed command must appear in `failed`, got %d", len(m.Failed))
	}
	if len(m.NotCollected) != len(in.Plan.Unbound) {
		t.Fatalf("not_collected has %d rows, plan listed %d unbound intents", len(m.NotCollected), len(in.Plan.Unbound))
	}
	if !strings.Contains(m.Redaction, "[REDACTED]") {
		t.Fatal("the manifest must state the redaction promise")
	}
	if m.ProblemStatement.WrittenBy != "template" {
		t.Fatalf("with no narrator the statement must be the template, got %q", m.ProblemStatement.WrittenBy)
	}
	var docClaimed bool
	for _, cmd := range m.Commands {
		if cmd.Verified == VerifiedDocClaimed && cmd.VerifiedNote == "" {
			t.Fatalf("doc_claimed command %q carries no plain-words note", cmd.Command)
		}
		if cmd.Verified == VerifiedDocClaimed {
			docClaimed = true
		}
	}
	if !docClaimed {
		t.Fatal("the fixture should contain at least one doc_claimed command")
	}
}

// TestBundleChecksums proves SHA256SUMS covers every entry and is correct.
func TestBundleChecksums(t *testing.T) {
	b, err := BuildBundle(context.Background(), fixtureBundleInput(t), nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	files := unzip(t, b.Zip)
	sums := map[string]string{}
	for _, line := range strings.Split(string(files["SHA256SUMS"]), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("malformed SHA256SUMS line %q", line)
		}
		sums[name] = sum
	}
	for name, data := range files {
		if name == "SHA256SUMS" {
			continue
		}
		want, ok := sums[name]
		if !ok {
			t.Errorf("%s has no checksum", name)
			continue
		}
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != want {
			t.Errorf("%s checksum mismatch", name)
		}
	}
}

// TestBundleIsDeterministic — the same inputs produce the same bytes.
func TestBundleIsDeterministic(t *testing.T) {
	in := fixtureBundleInput(t)
	a, _ := BuildBundle(context.Background(), in, nil, fixedClock())
	b, _ := BuildBundle(context.Background(), in, nil, fixedClock())
	if !bytes.Equal(a.Zip, b.Zip) {
		t.Fatal("two bundles from identical inputs differ")
	}
}

// TestBundleEmailProfileTrimsAndSaysSo.
func TestBundleEmailProfileTrimsAndSaysSo(t *testing.T) {
	in := fixtureBundleInput(t)
	big := strings.Repeat("z", 10<<20)
	in.Capture.Commands[2].Output = big
	in.Capture.Commands[2].Bytes = len(big)
	in.Capture.Commands[3].Output = big
	in.Capture.Commands[3].Bytes = len(big)
	in.Profile = ProfileEmail
	b, err := BuildBundle(context.Background(), in, nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	var m Manifest
	_ = json.Unmarshal(unzip(t, b.Zip)["MANIFEST.json"], &m)
	if len(m.Trimmed) == 0 {
		t.Fatal("the email profile did not trim anything for a 20 MB capture")
	}
	for _, tr := range m.Trimmed {
		if !strings.Contains(tr.Reason, "attachment limit") {
			t.Fatalf("a trim must say why: %q", tr.Reason)
		}
		if _, present := unzip(t, b.Zip)[tr.File]; present {
			t.Fatalf("%s is listed as trimmed but is still in the zip", tr.File)
		}
	}
	// The manifest must never point at a file that was trimmed away.
	files := unzip(t, b.Zip)
	for _, cmd := range m.Commands {
		if cmd.File == "" {
			continue
		}
		if _, ok := files[cmd.File]; !ok {
			t.Fatalf("manifest points at missing file %s", cmd.File)
		}
	}
}

// TestBundleNeedsACapture — no capture, no bundle.
func TestBundleNeedsACapture(t *testing.T) {
	if _, err := BuildBundle(context.Background(), BundleInput{}, nil, fixedClock()); err == nil {
		t.Fatal("expected a refusal for a bundle with no capture")
	}
}
