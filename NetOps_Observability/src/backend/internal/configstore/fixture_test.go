package configstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture_test.go — the in-package harness. Everything external is a fake, which
// is the point of the Deps design: the whole capture → seal → store → serve path
// runs with no device, no Postgres, no vault and no HTTP server.

// fakeSealer is a REAL (if trivial) cipher, not a passthrough: the round-trip
// test would be meaningless against an identity function, and the
// "no plaintext on disk" scan needs the stored bytes to genuinely differ from
// the config. It also enforces the AAD binding, so a blob copied between tenants
// or devices fails to open exactly as the vault's would.
type fakeSealer struct {
	active bool
	mu     sync.Mutex
	opened int
}

const fakeMarker = "fake1:"

func (f *fakeSealer) Active() bool { return f.active }
func (f *fakeSealer) Marker() string {
	return fakeMarker
}

func (f *fakeSealer) Seal(tenant, fieldID, plaintext string) (string, error) {
	if !f.active {
		return "", errors.New("sealer dormant")
	}
	body := xorWith(plaintext, tenant+"|"+fieldID)
	return fakeMarker + base64.StdEncoding.EncodeToString([]byte(body)), nil
}

func (f *fakeSealer) Open(tenant, fieldID, sealed string) (string, error) {
	f.mu.Lock()
	f.opened++
	f.mu.Unlock()
	if !strings.HasPrefix(sealed, fakeMarker) {
		return "", errors.New("not sealed")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, fakeMarker))
	if err != nil {
		return "", err
	}
	return xorWith(string(raw), tenant+"|"+fieldID), nil
}

// xorWith is a keystream XOR — enough to make the ciphertext unreadable and
// AAD-bound for the purposes of these tests.
func xorWith(s, key string) string {
	if key == "" {
		key = "k"
	}
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key[i%len(key)] ^ 0x5a
	}
	return string(out)
}

// fakeGateway answers capture commands from a script, records what was asked,
// and can be told to fail or to stall.
type fakeGateway struct {
	mu       sync.Mutex
	outputs  map[string]string // device id → raw config
	err      map[string]error  // device id → capture error
	commands []string
	devices  []string
	delay    time.Duration
	calls    int
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{outputs: map[string]string{}, err: map[string]error{}}
}

func (g *fakeGateway) set(deviceID, raw string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.outputs[deviceID] = raw
}

func (g *fakeGateway) fail(deviceID string, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err[deviceID] = err
}

func (g *fakeGateway) Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error) {
	g.mu.Lock()
	g.calls++
	g.commands = append(g.commands, command)
	g.devices = append(g.devices, dev.ID)
	out, ok := g.outputs[dev.ID]
	err := g.err[dev.ID]
	delay := g.delay
	g.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("device unreachable")
	}
	if int64(len(out)) > maxBytes {
		return "", ErrTooLarge
	}
	return out, nil
}

func (g *fakeGateway) callCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func (g *fakeGateway) lastCommand() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.commands) == 0 {
		return ""
	}
	return g.commands[len(g.commands)-1]
}

// fixture wires a Manager + API over the fakes.
type fixture struct {
	t       *testing.T
	mgr     *Manager
	api     *API
	store   *FileStore
	blobs   *FileBlobStore
	gw      *fakeGateway
	sealer  *fakeSealer
	metrics *Metrics
	root    string

	devices map[string]Device
	// principal is what the injected Authz returns; tests swap it to change
	// who is calling. It is the ONLY source of caller scope — no test can (or
	// should be able to) influence it through a query string.
	principal Principal
	authzOK   bool

	verdict  DriftVerdict
	captured []CaptureEvent
	failures []CaptureFailure
	audits   []map[string]any
	mu       sync.Mutex
	now      time.Time
}

func newFixture(t *testing.T, tune func(*Deps)) *fixture {
	t.Helper()
	root := t.TempDir()
	sealer := &fakeSealer{active: true}
	blobs, err := NewFileBlobStore(root+"/blobs", sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	f := &fixture{
		t: t, store: NewFileStore(""), blobs: blobs, gw: newFakeGateway(),
		sealer: sealer, metrics: NewMetrics(), root: root + "/blobs",
		devices: map[string]Device{}, authzOK: true,
		now:     time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		verdict: DriftVerdict{State: DriftChanged, Added: 1, Removed: 0},
	}
	d := Deps{
		Now:     func() time.Time { return f.now },
		Tenants: func() []string { return []string{"acme", "globex"} },
		Devices: func(tenant string) []Device {
			out := []Device{}
			for _, dev := range f.devices {
				if NormTenant(dev.TenantID) == NormTenant(tenant) {
					out = append(out, dev)
				}
			}
			return out
		},
		LookupDevice: func(id string) (Device, bool) {
			dev, ok := f.devices[id]
			return dev, ok
		},
		Gateway: f.gw, Sealer: sealer, Blobs: blobs, Store: f.store, Metrics: f.metrics,
		OnCapture: func(_ context.Context, ev CaptureEvent) DriftVerdict {
			f.mu.Lock()
			f.captured = append(f.captured, ev)
			f.mu.Unlock()
			return f.verdict
		},
		OnFailure: func(_ context.Context, cf CaptureFailure) {
			f.mu.Lock()
			f.failures = append(f.failures, cf)
			f.mu.Unlock()
		},
		Authz: func(w http.ResponseWriter, _ *http.Request, _ Gate) (Principal, bool) {
			if !f.authzOK {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			return f.principal, true
		},
		Audit: func(_ *http.Request, tenant, action string, detail map[string]any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			cp := map[string]any{"tenant": tenant, "action": action}
			for k, v := range detail {
				cp[k] = v
			}
			f.audits = append(f.audits, cp)
		},
		AuditCapture: func(tenant, deviceID, action string, detail map[string]any) {
			f.mu.Lock()
			defer f.mu.Unlock()
			cp := map[string]any{"tenant": tenant, "device": deviceID, "action": action}
			for k, v := range detail {
				cp[k] = v
			}
			f.audits = append(f.audits, cp)
		},
		WriteJSON:  testWriteJSON,
		WriteError: testWriteError,
		LogWarn:    func(string, map[string]any) {},
		LogError:   func(string, map[string]any) {},
		Scrub:      func(s string) string { return s },
		Interval:   time.Hour, KeepVersions: 3, CaptureTimeout: 2 * time.Second,
	}
	if tune != nil {
		tune(&d)
	}
	mgr, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.mgr = mgr
	f.api = NewAPI(mgr, nil)
	return f
}

func testWriteJSON(w http.ResponseWriter, status int, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		http.Error(w, "encode", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func testWriteError(w http.ResponseWriter, status int, err error) {
	testWriteJSON(w, status, map[string]string{"error": err.Error()})
}

func (f *fixture) addDevice(id, tenant, platform string) Device {
	dev := Device{ID: id, Name: id + "-name", Address: "10.0.0.9", Vendor: platform, TenantID: tenant}
	f.devices[id] = dev
	return dev
}

// do issues one request through the device subtree dispatcher.
func (f *fixture) do(method, path string, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	if !f.api.ServeDeviceSubroute(w, r) {
		f.t.Fatalf("route %s %s was not dispatched", method, path)
	}
	return w
}

func (f *fixture) decode(w *httptest.ResponseRecorder) map[string]any {
	f.t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

func (f *fixture) auditActions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.audits))
	for _, a := range f.audits {
		out = append(out, fmt.Sprint(a["action"]))
	}
	return out
}

// sampleConfig is the canonical Cisco config the capture tests use — it carries
// a volatile header AND a live secret canary, so one fixture exercises both
// normalization and redaction.
func sampleConfig(marker string) string {
	return "Building configuration...\n" +
		"! Last configuration change at 10:00:00 UTC Mon Aug 25 2026\n" +
		"hostname " + marker + "\n" +
		"enable secret 5 " + canaryEnableSecret + "\n" +
		"snmp-server community " + canaryCommunity + " RO\n" +
		"interface Gi0/0\n" +
		" ip address 10.0.0.1 255.255.255.0\n"
}
