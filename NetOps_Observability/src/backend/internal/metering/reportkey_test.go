package metering

// reportkey_test.go — the per-installation signing identity.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReportKeyIsGeneratedOnceAndSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-report-key.json")
	k := NewReportKey(path, nil)
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("construction touched the disk — an installation that never asks for a report must never grow a key")
	}

	first, ok := k.View()
	if !ok || first.ID == "" || first.Base64 == "" {
		t.Fatalf("no key view: %+v", first)
	}
	if first.Note == "" || !strings.Contains(first.Note, "not the key Correlix signs licences with") {
		t.Errorf("the key view must say what this key is NOT: %q", first.Note)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the key was not stored: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("the key file is %#o, want 0600", perm)
	}

	// A restart must reuse the identity: a key id that changes every boot makes
	// every previously filed report unattributable.
	again, ok := NewReportKey(path, nil).View()
	if !ok || again.ID != first.ID {
		t.Fatalf("the key id changed across a restart: %q then %q", first.ID, again.ID)
	}
	if k.Ephemeral() {
		t.Errorf("a stored key reported itself ephemeral")
	}
}

func TestReportKeyRefusesToReplaceAnUnreadableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "licence-report-key.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var warned string
	k := NewReportKey(path, func(msg string, _ error) { warned = msg })
	if _, _, err := k.Private(); err == nil {
		t.Fatalf("a corrupt key file was silently replaced — every report already filed under the old identity would become unattributable")
	}
	if warned == "" {
		t.Errorf("the failure was not reported (§10: no silent failures)")
	}
	if k.Err() == nil {
		t.Errorf("Err() reports no problem after a failed load")
	}
}

func TestReportKeyWithNoPathSignsButSaysItIsEphemeral(t *testing.T) {
	k := NewReportKey("", nil)
	priv, _, err := k.Private()
	if err != nil {
		t.Fatalf("private: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("key is %d bytes", len(priv))
	}
	if !k.Ephemeral() {
		t.Errorf("a key with nowhere to live must report itself ephemeral")
	}
}

func TestReportKeyGenerationFailureRefusesTheReport(t *testing.T) {
	k := NewReportKey("", nil)
	k.rnd = func() (ed25519.PublicKey, ed25519.PrivateKey, error) { return nil, nil, errors.New("no entropy") }
	if _, _, err := k.Private(); err == nil {
		t.Fatalf("a report was signable with no key — an unsigned document offered as a signed one is worse than none")
	}
	if _, ok := k.View(); ok {
		t.Errorf("a view was produced with no key")
	}
}

func TestNilReportKeyIsSafe(t *testing.T) {
	var k *ReportKey
	if _, _, err := k.Private(); err == nil {
		t.Errorf("a nil key signed something")
	}
	if _, ok := k.View(); ok {
		t.Errorf("a nil key produced a view")
	}
	if k.Path() != "" || k.Err() != nil || k.Ephemeral() {
		t.Errorf("a nil key is not inert")
	}
}

func TestFingerprintMatchesTheLicenceKeyConstruction(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	fp := Fingerprint(pub)
	if len(fp) != 16 {
		t.Fatalf("fingerprint %q is %d hex chars, want 16 (the first 8 bytes of the SHA-256)", fp, len(fp))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Recorder
// ─────────────────────────────────────────────────────────────────────────────

func TestRecorderSnapshotAndMetrics(t *testing.T) {
	store := NewFileStore("")
	at := day("2026-09-05T01:00:00Z")
	r := NewRecorder(store, func(context.Context) map[string][]Reading {
		return map[string][]Reading{
			"acme":            {Unique(MeterMonitoredDevicesUnique, "acme", []string{"d1"})},
			ScopeInstallation: {Measured(MeterTenants, ScopeInstallation, 1)},
		}
	}, nil)
	r.now = func() time.Time { return at }
	if err := r.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if got := r.LastSnapshot(); !got.Equal(at) {
		t.Fatalf("last snapshot = %v, want %v", got, at)
	}
	var b strings.Builder
	r.WriteMetrics(&b)
	out := b.String()
	for _, want := range []string{MetricSnapshotTimestamp, MetricDailyRows, MetricSnapshotFailures, MetricPrunedRows} {
		if !strings.Contains(out, "# TYPE "+want+" ") {
			t.Errorf("%s is not emitted", want)
		}
	}
	if !strings.Contains(out, MetricDailyRows+" 2\n") {
		t.Errorf("the row gauge does not read 2:\n%s", out)
	}
}

func TestRecorderNeverGoesQuietOnFailure(t *testing.T) {
	var warned string
	r := NewRecorder(brokenStore{}, func(context.Context) map[string][]Reading { return nil },
		func(msg string, _ error) { warned = msg })
	if err := r.Snapshot(context.Background()); err == nil {
		t.Fatalf("a failed snapshot reported success")
	}
	if warned == "" {
		t.Errorf("a failed snapshot was not reported (§10: no silent failures)")
	}
	var b strings.Builder
	r.WriteMetrics(&b)
	if !strings.Contains(b.String(), MetricSnapshotFailures+" 1\n") {
		t.Errorf("the failure counter did not move:\n%s", b.String())
	}
	// The timestamp stays 0 rather than moving on a failure: a stale value is
	// what the alert rule is FOR.
	if !strings.Contains(b.String(), MetricSnapshotTimestamp+" 0\n") {
		t.Errorf("a failed snapshot advanced the timestamp:\n%s", b.String())
	}
}

func TestUnwiredRecorderIsInertAndSaysSo(t *testing.T) {
	var r *Recorder
	if err := r.Snapshot(context.Background()); err == nil {
		t.Errorf("an unwired recorder claimed to record something")
	}
	if !r.LastSnapshot().IsZero() {
		t.Errorf("an unwired recorder has a snapshot time")
	}
	var b strings.Builder
	r.WriteMetrics(&b)
	if !strings.Contains(b.String(), MetricSnapshotTimestamp+" 0\n") {
		t.Errorf("an unwired recorder must still emit the series, as a zero:\n%s", b.String())
	}
}
