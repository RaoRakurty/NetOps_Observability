package configstore

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCaptureSealsAndStoresNoPlaintextOnDisk is the module's headline security
// contract: after a capture, the configuration exists on the volume ONLY as
// ciphertext. The test walks the entire blob directory looking for the canary
// secret AND for a plain configuration keyword — either one on disk is a failure.
func TestCaptureSealsAndStoresNoPlaintextOnDisk(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE 17.9")
	f.gw.set("d1", sampleConfig("edge-01"))

	v, err := f.mgr.Capture(context.Background(), dev, "acme", "test")
	if err != nil {
		t.Fatalf("Capture: %v", err)
	}
	if v.Status != StatusOK || v.SHA == "" || v.BlobRef == "" {
		t.Fatalf("unexpected version: %+v", v)
	}
	if f.gw.lastCommand() != "show running-config" {
		t.Fatalf("wrong capture command: %q", f.gw.lastCommand())
	}

	// Walk the store directory for anything readable.
	var offenders []string
	err = filepath.Walk(f.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Mode().Perm() != 0o700 {
				t.Errorf("blob directory %s mode = %v, want 0700", path, info.Mode().Perm())
			}
			return nil
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("blob %s mode = %v, want 0600", path, info.Mode().Perm())
		}
		b, rerr := os.ReadFile(path) // #nosec G304 -- test walks its own temp dir
		if rerr != nil {
			return rerr
		}
		body := string(b)
		for _, canary := range []string{canaryEnableSecret, canaryCommunity,
			"hostname edge-01", "snmp-server community", "interface Gi0/0"} {
			if strings.Contains(body, canary) {
				offenders = append(offenders, path+" contains "+canary)
			}
		}
		if !strings.HasPrefix(body, fakeMarker) {
			offenders = append(offenders, path+" is not sealed")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("PLAINTEXT ON DISK: %v", offenders)
	}

	// Round-trip: the sealed copy still opens to the ORIGINAL text (unredacted —
	// that is the artifact an operator restores from).
	text, err := f.mgr.Open(v)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !strings.Contains(text, canaryEnableSecret) {
		t.Fatal("the sealed copy must keep the original secret material")
	}
	if strings.Contains(text, "Last configuration change") {
		t.Fatal("the stored version must be the NORMALIZED config")
	}
}

// TestCaptureRefusesWhenSealingIsDormant: the module will not run at all rather
// than write device configurations in cleartext.
func TestCaptureRefusesWhenSealingIsDormant(t *testing.T) {
	dormant := &fakeSealer{active: false}
	root := t.TempDir()
	blobs, err := NewFileBlobStore(root, dormant.Marker())
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Deps{
		Now: time.Now, Tenants: func() []string { return nil },
		Devices:      func(string) []Device { return nil },
		LookupDevice: func(string) (Device, bool) { return Device{}, false },
		Gateway:      newFakeGateway(), Sealer: dormant, Blobs: blobs, Store: NewFileStore(""),
		Authz:      func(http.ResponseWriter, *http.Request, Gate) (Principal, bool) { return Principal{}, false },
		WriteJSON:  func(http.ResponseWriter, int, any) {},
		WriteError: func(http.ResponseWriter, int, error) {},
		LogWarn:    func(string, map[string]any) {},
		LogError:   func(string, map[string]any) {},
		Scrub:      func(s string) string { return s },
	})
	if err == nil {
		t.Fatal("a dormant sealing provider must refuse construction")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("the refusal must say why: %v", err)
	}
}

// TestBlobStoreRefusesUnsealedWrite is the structural guard under the invariant.
func TestBlobStoreRefusesUnsealedWrite(t *testing.T) {
	b, err := NewFileBlobStore(t.TempDir(), "v1:")
	if err != nil {
		t.Fatal(err)
	}
	sha := SHA256Hex("x")
	if _, err := b.Put("acme", "d1", sha, "hostname plaintext"); err == nil {
		t.Fatal("an unsealed blob must be refused")
	}
	if _, err := b.Put("acme", "d1", "not-a-sha", "v1:sealed"); err == nil {
		t.Fatal("an invalid version id must be refused")
	}
	// A reference that escapes the root is refused even though it "came from the
	// database".
	if _, err := b.Get("../../etc/passwd"); err == nil {
		t.Fatal("a blob reference escaping the root must be refused")
	}
}

// TestCaptureUnchangedStoresNoNewVersion is the content-addressing promise: a
// fleet that is not changing costs no storage.
func TestCaptureUnchangedStoresNoNewVersion(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))

	v1, err := f.mgr.Capture(context.Background(), dev, "acme", "t1")
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	// A second capture whose only difference is the volatile timestamp header.
	f.gw.set("d1", strings.Replace(sampleConfig("edge-01"),
		"10:00:00 UTC Mon Aug 25 2026", "11:00:00 UTC Mon Aug 25 2026", 1))
	v2, err := f.mgr.Capture(context.Background(), dev, "acme", "t2")
	if err != nil {
		t.Fatal(err)
	}
	if v1.SHA != v2.SHA {
		t.Fatalf("volatile-only change minted a new version: %s → %s", v1.SHA, v2.SHA)
	}
	rows, _ := f.store.List(context.Background(), "acme", false, "d1")
	if len(rows) != 1 {
		t.Fatalf("stored %d versions, want 1", len(rows))
	}
	if !rows[0].CapturedAt.Equal(f.now) {
		t.Error("an unchanged capture must advance last-verified time")
	}
	if got := f.metrics.Snapshot()["runs_"+OutcomeUnchanged]; got != 1 {
		t.Errorf("unchanged runs = %d, want 1", got)
	}
	if got := f.metrics.Snapshot()["versions_total"]; got != 1 {
		t.Errorf("versions_total = %d, want 1", got)
	}
	if f.metrics.Snapshot()["bytes_sealed_total"] <= 0 {
		t.Error("bytes_sealed_total must move on a new version")
	}
}

// TestRetentionPrunesOldestAndKeepsGolden.
func TestRetentionPrunesOldestAndKeepsGolden(t *testing.T) {
	f := newFixture(t, nil) // KeepVersions: 3
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	ctx := context.Background()

	shas := []string{}
	for i := 0; i < 6; i++ {
		f.now = f.now.Add(time.Duration(i+1) * time.Hour)
		f.gw.set("d1", sampleConfig("edge-"+string(rune('a'+i))))
		v, err := f.mgr.Capture(ctx, dev, "acme", "t")
		if err != nil {
			t.Fatal(err)
		}
		shas = append(shas, v.SHA)
		if i == 0 {
			// The FIRST version becomes golden — retention must never take it.
			if err := f.store.SetGolden(ctx, "acme", false, "d1", v.SHA); err != nil {
				t.Fatal(err)
			}
		}
	}
	rows, _ := f.store.List(ctx, "acme", false, "d1")
	if len(rows) != 4 { // 3 kept + the golden
		t.Fatalf("retention kept %d versions, want 4 (3 + golden)", len(rows))
	}
	found := false
	for _, r := range rows {
		if r.SHA == shas[0] {
			found = r.Golden
		}
	}
	if !found {
		t.Fatal("retention pruned the golden baseline")
	}
	// The pruned blobs are gone from disk too — no orphans.
	var files int
	_ = filepath.Walk(f.root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files++
		}
		return nil
	})
	if files != 4 {
		t.Fatalf("blob directory holds %d files, want 4", files)
	}
}

// TestCaptureFailureIsRecordedAndObserved: an unreachable device produces a
// FAILED row and a failure notification — never silence, never a stale green.
func TestCaptureFailureIsRecordedAndObserved(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.fail("d1", errors.New("connect: connection refused"))

	if _, err := f.mgr.Capture(context.Background(), dev, "acme", "t"); err == nil {
		t.Fatal("an unreachable device must fail the capture")
	}
	rows, _ := f.store.List(context.Background(), "acme", false, "d1")
	if len(rows) != 1 || rows[0].Status != StatusFailed {
		t.Fatalf("failed capture not recorded: %+v", rows)
	}
	if rows[0].Error == "" || rows[0].Drift != DriftUnknown {
		t.Fatalf("failed row must carry the reason and an unknown verdict: %+v", rows[0])
	}
	f.mu.Lock()
	n := len(f.failures)
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("failure observer called %d times, want 1", n)
	}
	if got := f.metrics.Snapshot()["runs_"+OutcomeFailed]; got != 1 {
		t.Errorf("failed runs = %d, want 1", got)
	}
}

// TestUnboundVendorIsRefused: no guessed command ever runs at a device prompt.
func TestUnboundVendorIsRefused(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "MysteryVendor MagicOS")
	f.gw.set("d1", "whatever")
	_, err := f.mgr.Capture(context.Background(), dev, "acme", "t")
	if !errors.Is(err, ErrNoVendor) {
		t.Fatalf("err = %v, want ErrNoVendor", err)
	}
	if f.gw.callCount() != 0 {
		t.Fatal("an unbound platform must not be dialled at all")
	}
}

// TestSingleFlightPerDevice is the 429 condition and the §9 overlap rule.
func TestSingleFlightPerDevice(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))
	f.gw.delay = 150 * time.Millisecond

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.mgr.Capture(context.Background(), dev, "acme", "t")
		}(i)
	}
	wg.Wait()

	inflightRefusals := 0
	for _, err := range errs {
		if errors.Is(err, ErrInFlight) {
			inflightRefusals++
		}
	}
	if inflightRefusals != 1 {
		t.Fatalf("expected exactly one ErrInFlight refusal, got %v", errs)
	}
	if f.gw.callCount() != 1 {
		t.Fatalf("gateway dialled %d times, want 1", f.gw.callCount())
	}
	if got := f.metrics.Snapshot()["runs_"+OutcomeSkipped]; got != 1 {
		t.Errorf("skipped runs = %d, want 1", got)
	}
}

// TestSweepTryLockDoesNotOverlap: a sweep already in flight makes the next one
// YIELD rather than queue.
func TestSweepTryLockDoesNotOverlap(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))
	f.gw.delay = 200 * time.Millisecond

	done := make(chan int, 1)
	go func() { done <- f.mgr.Sweep(context.Background()) }()
	time.Sleep(40 * time.Millisecond)
	if n := f.mgr.Sweep(context.Background()); n != 0 {
		t.Fatalf("overlapping sweep attempted %d devices, want 0", n)
	}
	if n := <-done; n != 1 {
		t.Fatalf("first sweep attempted %d devices, want 1", n)
	}
}

// TestSweepIsTenantScoped: a sweep only ever captures a tenant's OWN devices,
// and stamps the DEVICE's tenant on the version (§3a rule 2).
func TestSweepIsTenantScoped(t *testing.T) {
	f := newFixture(t, nil)
	f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.addDevice("d2", "globex", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("acme-edge"))
	f.gw.set("d2", sampleConfig("globex-edge"))

	if n := f.mgr.Sweep(context.Background()); n != 2 {
		t.Fatalf("sweep attempted %d devices, want 2", n)
	}
	ctx := context.Background()
	acme, _ := f.store.List(ctx, "acme", false, "d1")
	if len(acme) != 1 || acme[0].TenantID != "acme" {
		t.Fatalf("acme device stamped wrong: %+v", acme)
	}
	// acme must not be able to see globex's version at all.
	foreign, _ := f.store.List(ctx, "acme", false, "d2")
	if len(foreign) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: acme sees %d globex versions", len(foreign))
	}
	if _, err := f.store.Get(ctx, "acme", false, "d2", acme[0].SHA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get = %v, want ErrNotFound", err)
	}
}

// TestCaptureHandsPreviousAndGoldenToTheObserver: the drift consumer gets the
// comparison inputs, and the verdict it returns is stamped on the row.
func TestCaptureHandsPreviousAndGoldenToTheObserver(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	ctx := context.Background()

	f.gw.set("d1", sampleConfig("edge-01"))
	v1, err := f.mgr.Capture(ctx, dev, "acme", "t")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetGolden(ctx, "acme", false, "d1", v1.SHA); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(time.Hour)
	f.gw.set("d1", sampleConfig("edge-02"))
	f.verdict = DriftVerdict{State: DriftDrifted, Added: 1, Removed: 1}
	v2, err := f.mgr.Capture(ctx, dev, "acme", "t")
	if err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	ev := f.captured[len(f.captured)-1]
	f.mu.Unlock()
	if !ev.HasPrevious || ev.PreviousSHA != v1.SHA || !strings.Contains(ev.Previous, "edge-01") {
		t.Fatalf("observer did not receive the previous version: %+v", ev.PreviousSHA)
	}
	if !ev.HasGolden || ev.GoldenSHA != v1.SHA || !strings.Contains(ev.Golden, "edge-01") {
		t.Fatal("observer did not receive the golden baseline")
	}
	if !strings.Contains(ev.Current, "edge-02") {
		t.Fatal("observer did not receive the current capture")
	}
	stored, err := f.store.Get(ctx, "acme", false, "d1", v2.SHA)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Drift != DriftDrifted || stored.Added != 1 || stored.Removed != 1 {
		t.Fatalf("verdict not stamped on the version row: %+v", stored)
	}
}

// TestCaptureIsAudited: every capture leaves an audit trail entry.
func TestCaptureIsAudited(t *testing.T) {
	f := newFixture(t, nil)
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))
	if _, err := f.mgr.Capture(context.Background(), dev, "acme", "scheduled"); err != nil {
		t.Fatal(err)
	}
	acts := f.auditActions()
	if len(acts) != 1 || acts[0] != "config_backup_capture" {
		t.Fatalf("audit actions = %v", acts)
	}
}

// TestCaptureBoundedByTimeout: a stalled device does not pin a goroutine past
// the capture timeout (§9 all IO has a timeout).
func TestCaptureBoundedByTimeout(t *testing.T) {
	f := newFixture(t, func(d *Deps) { d.CaptureTimeout = 50 * time.Millisecond })
	dev := f.addDevice("d1", "acme", "Cisco IOS-XE")
	f.gw.set("d1", sampleConfig("edge-01"))
	f.gw.delay = 5 * time.Second

	start := time.Now()
	_, err := f.mgr.Capture(context.Background(), dev, "acme", "t")
	if err == nil {
		t.Fatal("a stalled capture must fail")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("capture ran %v past its timeout", elapsed)
	}
}
