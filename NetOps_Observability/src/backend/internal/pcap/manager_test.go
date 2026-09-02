package pcap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// manager_test.go — the GUARDRAILS. Every bound the design calls
// non-negotiable is asserted here, from both directions: the request is refused
// with a reason, and nothing reached the device.

func TestGuardrailsRefuseOutOfBoundRequests(t *testing.T) {
	for _, tc := range []struct {
		name string
		req  StartRequest
		want string
	}{
		{"duration over the cap", StartRequest{Interface: "Ethernet1/1", DurationSec: MaxDurationSeconds + 1}, "duration_s"},
		{"duration far over the cap", StartRequest{Interface: "Ethernet1/1", DurationSec: 3600}, "duration_s"},
		{"negative duration", StartRequest{Interface: "Ethernet1/1", DurationSec: -1}, "duration_s"},
		{"packets over the cap", StartRequest{Interface: "Ethernet1/1", MaxPackets: MaxPackets + 1}, "max_packets"},
		{"negative packets", StartRequest{Interface: "Ethernet1/1", MaxPackets: -5}, "max_packets"},
		{"no interface", StartRequest{}, "interface"},
		{"hostile interface", StartRequest{Interface: "eth0; reboot"}, "interface"},
		{"hostile filter", StartRequest{Interface: "Ethernet1/1", Filter: "host 1.2.3.4; reload"}, "filter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t, nil)
			_, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"], tc.req, "a@acme")
			if err == nil {
				t.Fatalf("the guardrail did not refuse %+v", tc.req)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name the bound (%q) — the operator cannot act on it", err, tc.want)
			}
			if cmds := fx.gw.all(); len(cmds) != 0 {
				t.Fatalf("a refused capture still reached the device: %v", cmds)
			}
			if got := fx.metrics.Snapshot()["runs_"+OutcomeRefused]; got != 1 {
				t.Fatalf("refused runs = %d, want 1", got)
			}
		})
	}
}

func TestGuardrailsAcceptTheBoundaryValues(t *testing.T) {
	fx := newFixture(t, nil)
	b, err := CheckBounds(StartRequest{Interface: "Ethernet1/1", DurationSec: MaxDurationSeconds, MaxPackets: MaxPackets})
	if err != nil {
		t.Fatalf("the exact bound was refused: %v", err)
	}
	if b.DurationSec != MaxDurationSeconds || b.MaxPackets != MaxPackets || b.MaxBytes != MaxBytes {
		t.Fatalf("bounds = %+v, want the caps", b)
	}
	// Unset fields take the small defaults the design asks for, not the caps.
	b, err = CheckBounds(StartRequest{Interface: "Ethernet1/1"})
	if err != nil {
		t.Fatal(err)
	}
	if b.DurationSec != DefaultDurationSeconds || b.MaxPackets != DefaultPackets {
		t.Fatalf("defaults = %+v, want %d s / %d packets", b, DefaultDurationSeconds, DefaultPackets)
	}
	_ = fx
}

func TestByteCapRefusesAnOversizedCapture(t *testing.T) {
	fx := newFixture(t, nil)
	fx.gw.oversize = true
	rec, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme")
	if err != nil {
		t.Fatalf("Start = %v", err)
	}
	stored, err := fx.store.Get(context.Background(), "acme", false, "acme-core", rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != StatusFailed {
		t.Fatalf("status = %q, want %q — an oversized capture must NOT be stored truncated", stored.Status, StatusFailed)
	}
	if stored.BlobRef != "" {
		t.Fatal("an oversized capture left a blob behind")
	}
	if !strings.Contains(stored.Error, "maximum capture size") {
		t.Fatalf("the stored reason %q does not say the size cap was hit", stored.Error)
	}
}

func TestOneCapturePerDeviceAtATime(t *testing.T) {
	// A capture that is still RUNNING must make the next request a 409. The
	// runner is made a no-op so the first capture stays in flight.
	fx := newFixture(t, func(d *Deps) { d.Run = func(func()) {} })
	first, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 5}, "a@acme")
	if err != nil {
		t.Fatalf("first Start = %v", err)
	}
	_, err = fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/2", DurationSec: 5}, "a@acme")
	if !errors.Is(err, ErrInFlight) {
		t.Fatalf("second Start = %v, want ErrInFlight", err)
	}
	if got := fx.metrics.Snapshot()["runs_"+OutcomeInFlight]; got != 1 {
		t.Fatalf("in_flight runs = %d, want 1", got)
	}
	// A DIFFERENT device is unaffected — the gate is per-device, not global.
	if _, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-iosxe"],
		StartRequest{Interface: "GigabitEthernet0/0/1", DurationSec: 5}, "a@acme"); err != nil {
		t.Fatalf("a second DEVICE was refused: %v", err)
	}
	_ = first
}

func TestAnExpiredRunningRowDoesNotWedgeTheDeviceForever(t *testing.T) {
	// The DURABLE half of the gate on its own: a running row left behind by a
	// runtime that died must stop blocking the device once it has expired, or a
	// crash would take that device permanently out of capture.
	fx := newFixture(t, nil)
	ctx := context.Background()
	stale := Capture{
		TenantID: "acme", DeviceID: "acme-core", ID: "00000000000000000000000000000001",
		Interface: "Ethernet1/1", Status: StatusRunning,
		StartedAt: fx.now.Add(-time.Hour), ExpiresAt: fx.now.Add(-time.Minute),
	}
	if err := fx.store.Put(ctx, "acme", false, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := fx.mgr.Start(ctx, fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme"); err != nil {
		t.Fatalf("an EXPIRED running row still blocked the device: %v", err)
	}

	// A row that has NOT expired still blocks it.
	fx2 := newFixture(t, nil)
	live := stale
	live.ExpiresAt = fx2.now.Add(time.Minute)
	if err := fx2.store.Put(ctx, "acme", false, live); err != nil {
		t.Fatal(err)
	}
	if _, err := fx2.mgr.Start(ctx, fx2.principal, fx2.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme"); !errors.Is(err, ErrInFlight) {
		t.Fatalf("a LIVE running row did not block the device: %v", err)
	}
}

func TestOneCaptureAtATimeAt409OverHTTP(t *testing.T) {
	fx := newFixture(t, func(d *Deps) { d.Run = func(func()) {} })
	w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1","duration_s":5}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first POST = %d (%s)", w.Code, w.Body.String())
	}
	var accepted struct {
		CaptureID string `json:"capture_id"`
		Status    string `json:"status"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Status != StatusRunning || !ValidateCaptureID(accepted.CaptureID) || accepted.ExpiresAt == "" {
		t.Fatalf("202 body = %+v, want {capture_id, status running, expires_at}", accepted)
	}
	w = fx.do(http.MethodPost, "/api/devices/acme-core/pcap", `{"interface":"Ethernet1/1","duration_s":5}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("second POST = %d, want 409 (%s)", w.Code, w.Body.String())
	}
}

func TestGuardrailBreachIsA400WithTheReason(t *testing.T) {
	fx := newFixture(t, nil)
	for _, body := range []string{
		`{"interface":"Ethernet1/1","duration_s":600}`,
		`{"interface":"Ethernet1/1","max_packets":999999}`,
		`{"interface":"eth0; reboot"}`,
		`{"interface":"Ethernet1/1","filter":"host 1.2.3.4; reload"}`,
		`{"interface":"Ethernet1/1","tenant_id":"globex"}`, // unknown field, rejected not ignored
	} {
		w := fx.do(http.MethodPost, "/api/devices/acme-core/pcap", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s = %d, want 400 (%s)", body, w.Code, w.Body.String())
		}
		if strings.TrimSpace(w.Body.String()) == "" {
			t.Errorf("POST %s returned a bare 400 with no reason", body)
		}
	}
}

func TestUnsupportedFilterAndPlatformAreHonestRefusals(t *testing.T) {
	fx := newFixture(t, nil)
	// IOS-XE cannot express a filter: refuse rather than capture wider than asked.
	w := fx.do(http.MethodPost, "/api/devices/acme-iosxe/pcap", `{"interface":"GigabitEthernet0/0/1","filter":"host 10.1.2.3"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot apply a capture filter") {
		t.Fatalf("filtered IOS-XE = %d (%s)", w.Code, w.Body.String())
	}
	// An unknown platform is refused, not guessed at.
	w = fx.do(http.MethodPost, "/api/devices/acme-mystery/pcap", `{"interface":"eth0"}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no packet-capture command set") {
		t.Fatalf("unknown platform = %d (%s)", w.Code, w.Body.String())
	}
	if cmds := fx.gw.all(); len(cmds) != 0 {
		t.Fatalf("a refused capture still reached a device: %v", cmds)
	}
}

func TestSuccessfulCaptureIsSealedAtRestAndCleanedUp(t *testing.T) {
	fx := newFixture(t, nil)
	rec, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1, Filter: "tcp and port 22"}, "a@acme")
	if err != nil {
		t.Fatalf("Start = %v", err)
	}
	stored, err := fx.store.Get(context.Background(), "acme", false, "acme-core", rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != StatusStored {
		t.Fatalf("status = %q (%s), want stored", stored.Status, stored.Error)
	}
	if stored.Packets != 3 {
		t.Fatalf("packets = %d, want 3 (counted from the pcap bytes)", stored.Packets)
	}
	if stored.Bytes != int64(len(fx.gw.payload)) {
		t.Fatalf("bytes = %d, want %d", stored.Bytes, len(fx.gw.payload))
	}

	// NO PLAINTEXT AT REST. Walk every file under the blob root and assert none
	// of them contains the capture's magic bytes or its payload.
	found := 0
	err = filepath.Walk(fx.blobs.Root(), func(p string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return werr
		}
		found++
		if info.Mode().Perm() != 0o600 {
			t.Errorf("sealed capture %s has mode %v, want 0600", p, info.Mode().Perm())
		}
		b, rerr := os.ReadFile(p) // #nosec G304 -- test-owned temp path
		if rerr != nil {
			return rerr
		}
		if !strings.HasPrefix(string(b), fakeMarker) {
			t.Errorf("%s does not carry the sealer marker — it may not be sealed", p)
		}
		if strings.Contains(string(b), string(fx.gw.payload)) {
			t.Errorf("PLAINTEXT AT REST: %s contains the raw capture bytes", p)
		}
		for _, magic := range pcapMagic {
			if strings.Contains(string(b), string(magic)) {
				t.Errorf("PLAINTEXT AT REST: %s contains a pcap magic number", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no blob was written — the at-rest scan would be vacuous")
	}

	// The capture point was torn down: cleanup ran.
	cmds := strings.Join(fx.gw.all(), "\n")
	if !strings.Contains(cmds, "delete ") {
		t.Fatalf("no cleanup command ran — a capture file may remain on the device:\n%s", cmds)
	}
	// And Open round-trips through the seal.
	raw, err := fx.mgr.Open(stored)
	if err != nil {
		t.Fatalf("Open = %v", err)
	}
	if string(raw) != string(fx.gw.payload) {
		t.Fatal("the unsealed capture does not match what the device produced")
	}
}

func TestSealedBlobIsBoundToItsTenantAndDevice(t *testing.T) {
	fx := newFixture(t, nil)
	rec, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme")
	if err != nil {
		t.Fatal(err)
	}
	stored, err := fx.store.Get(context.Background(), "acme", false, "acme-core", rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A row whose tenant has been tampered with cannot open its own blob: the
	// AAD binds the ciphertext to (tenant, device, capture), so a blob moved
	// between tenants is unreadable rather than mis-served.
	tampered := stored
	tampered.TenantID = "globex"
	if _, err := fx.mgr.Open(tampered); err == nil {
		t.Fatal("a blob opened under ANOTHER tenant's key — the AAD binding is not enforced")
	}
	tampered = stored
	tampered.DeviceID = "globex-core"
	if _, err := fx.mgr.Open(tampered); err == nil {
		t.Fatal("a blob opened under ANOTHER device's field id — the AAD binding is not enforced")
	}
}

func TestManagerRefusesToRunWithADormantSealer(t *testing.T) {
	// §8: rather than write packet payload in cleartext, the module refuses to
	// exist. This is the fail-closed half of "encryption at rest".
	dir := t.TempDir()
	sealer := &fakeSealer{active: false}
	blobs, err := NewFileBlobStore(dir, "fake1:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Deps{
		Now: time.Now, LookupDevice: func(string) (Device, bool) { return Device{}, false },
		Gateway: &fakeGateway{}, Commands: NewDefaultCommandTable(), Sealer: sealer,
		Blobs: blobs, Store: NewFileStore(""),
		Authz:      func(http.ResponseWriter, *http.Request, Gate) (Principal, bool) { return Principal{}, false },
		WriteJSON:  testWriteJSON,
		WriteError: testWriteError,
		LogWarn:    func(string, map[string]any) {}, LogError: func(string, map[string]any) {},
		Scrub: func(s string) string { return s },
	})
	if err == nil {
		t.Fatal("the manager was built over a DORMANT sealer — captures would be written in cleartext")
	}
	if !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("the refusal %q does not say why", err)
	}
}

func TestNewRefusesIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New accepted an empty Deps — a silently non-capturing manager")
	}
}

func TestRetentionPrunesOldestAndDeletesBlobs(t *testing.T) {
	fx := newFixture(t, func(d *Deps) { d.Keep = 2 })
	ctx := context.Background()
	refs := []string{}
	for i := 0; i < 4; i++ {
		fx.now = fx.now.Add(time.Minute)
		rec, err := fx.mgr.Start(ctx, fx.principal, fx.devices["acme-core"],
			StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme")
		if err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		stored, err := fx.store.Get(ctx, "acme", false, "acme-core", rec.ID)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, stored.BlobRef)
	}
	rows, err := fx.store.List(ctx, "acme", false, "acme-core", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("retention kept %d rows, want 2", len(rows))
	}
	// The pruned blobs are GONE, not merely unreferenced: an unreachable sealed
	// payload on disk is still payload on disk.
	for _, ref := range refs[:2] {
		if _, err := fx.blobs.Get(ref); !errors.Is(err, ErrNotFound) {
			t.Errorf("pruned blob %s still exists (%v)", ref, err)
		}
	}
	if got := fx.metrics.Snapshot()["pruned_total"]; got != 2 {
		t.Fatalf("pruned_total = %d, want 2", got)
	}
}

func TestTheDeviceFetchIsAuditedSeparatelyFromTheStart(t *testing.T) {
	// "A capture started" and "packet payload left the device" are different
	// facts, and the audit trail has to be able to answer both.
	var runtime []map[string]any
	var tenants []string
	fx := newFixture(t, func(d *Deps) {
		d.AuditRuntime = func(tenant, device, action string, detail map[string]any) {
			if action != "pcap_capture_fetched" {
				return
			}
			tenants = append(tenants, tenant)
			detail["device"] = device
			runtime = append(runtime, detail)
		}
	})
	if _, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1, Filter: "tcp and port 22"}, "a@acme"); err != nil {
		t.Fatal(err)
	}
	if len(runtime) != 1 {
		t.Fatalf("fetch audits = %d, want 1", len(runtime))
	}
	if runtime[0]["sensitive"] != true {
		t.Fatalf("the fetch audit is not tagged sensitive: %+v", runtime[0])
	}
	if tenants[0] != "acme" || runtime[0]["device"] != "acme-core" || runtime[0]["actor"] != "a@acme" {
		t.Fatalf("the fetch audit does not identify whose payload moved: %v / %+v", tenants, runtime[0])
	}
	if runtime[0]["filter"] != "tcp and port 22" {
		t.Fatalf("the fetch audit does not record how wide the capture was: %+v", runtime[0])
	}

	// A capture that FAILED never emits a fetch audit — no payload moved.
	fx2 := newFixture(t, func(d *Deps) {
		d.AuditRuntime = func(_, _, action string, _ map[string]any) {
			if action == "pcap_capture_fetched" {
				t.Errorf("a FAILED capture claimed payload had left the device")
			}
		}
	})
	fx2.gw.fetchErr = errors.New("device unreachable")
	if _, err := fx2.mgr.Start(context.Background(), fx2.principal, fx2.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme"); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsCoverTheDocumentedSeries(t *testing.T) {
	fx := newFixture(t, nil)
	if _, err := fx.mgr.Start(context.Background(), fx.principal, fx.devices["acme-core"],
		StartRequest{Interface: "Ethernet1/1", DurationSec: 1}, "a@acme"); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fx.metrics.Write(&b)
	out := b.String()
	for _, want := range []string{
		`netops_pcap_captures_total{outcome="stored"} 1`,
		`netops_pcap_captures_total{outcome="failed"} 0`,
		"netops_pcap_bytes_sealed_total",
		"netops_pcap_active 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics is missing %q:\n%s", want, out)
		}
	}
}
