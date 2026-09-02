package pcap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixture_test.go — the in-package harness. Everything external is a fake, which
// is the point of the Deps design: the whole start → bound → fetch → seal →
// store → serve path runs with no device, no Postgres, no vault and no network.

// fakeSealer is a REAL (if trivial) cipher, not a passthrough: the
// "no plaintext at rest" scan needs the stored bytes to genuinely differ from
// the capture, and the AAD binding must make a blob copied between tenants or
// devices fail to open exactly as the vault's would.
type fakeSealer struct {
	active bool
	mu     sync.Mutex
	opened int
}

const fakeMarker = "fake1:"

func (f *fakeSealer) Active() bool   { return f.active }
func (f *fakeSealer) Marker() string { return fakeMarker }

// The sealed form is `fake1:` + base64(aadTag || xor(plaintext)). The tag makes
// the AAD BINDING real: opening under a different tenant or device fails the
// way the vault's AES-GCM would, rather than silently returning garbage.
func (f *fakeSealer) Seal(tenant, fieldID, plaintext string) (string, error) {
	if !f.active {
		return "", errors.New("sealer dormant")
	}
	aad := tenant + "|" + fieldID
	tag := sha256.Sum256([]byte(aad))
	body := append(append([]byte{}, tag[:8]...), []byte(xorWith(plaintext, aad))...)
	return fakeMarker + base64.StdEncoding.EncodeToString(body), nil
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
	if len(raw) < 8 {
		return "", errors.New("truncated blob")
	}
	aad := tenant + "|" + fieldID
	tag := sha256.Sum256([]byte(aad))
	if !bytes.Equal(raw[:8], tag[:8]) {
		// Exactly what AES-GCM does on an AAD mismatch: refuse, never decrypt.
		return "", errors.New("aad mismatch: this blob does not belong to this tenant/device")
	}
	return xorWith(string(raw[8:]), aad), nil
}

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

// fakeGateway records every command it was asked to run and answers Fetch from a
// scripted payload. Recording the commands is the point: the injection tests
// assert on the EXACT bytes that would have reached the device.
type fakeGateway struct {
	mu       sync.Mutex
	commands []string
	payload  []byte
	execErr  error
	fetchErr error
	// fetchSize, when > 0, is reported instead of len(payload) so the size cap
	// can be exercised without allocating 25 MiB.
	oversize bool
}

func (f *fakeGateway) Exec(_ context.Context, _ Device, command string, _ int64) (string, error) {
	f.mu.Lock()
	f.commands = append(f.commands, command)
	f.mu.Unlock()
	if f.execErr != nil {
		return "", f.execErr
	}
	return "", nil
}

func (f *fakeGateway) Fetch(_ context.Context, _ Device, remotePath string, maxBytes int64) ([]byte, error) {
	f.mu.Lock()
	f.commands = append(f.commands, "FETCH "+remotePath)
	f.mu.Unlock()
	if f.fetchErr != nil {
		return nil, f.fetchErr
	}
	if f.oversize {
		return nil, ErrTooLarge
	}
	if int64(len(f.payload)) > maxBytes {
		return nil, ErrTooLarge
	}
	return f.payload, nil
}

func (f *fakeGateway) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.commands))
	copy(out, f.commands)
	return out
}

// samplePCAP builds a tiny but STRUCTURALLY REAL libpcap file with n records, so
// the packet count on the listing is computed from bytes rather than asserted
// against a number the test also invented.
func samplePCAP(n int) []byte {
	out := make([]byte, 0, 24+n*(16+4))
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4) // stored little-endian => d4 c3 b2 a1 on the wire
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // LINKTYPE_ETHERNET
	out = append(out, hdr...)
	for i := 0; i < n; i++ {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(rec[8:], 4)  // caplen
		binary.LittleEndian.PutUint32(rec[12:], 4) // origlen
		out = append(out, rec...)
		out = append(out, 0xde, 0xad, 0xbe, 0xef)
	}
	return out
}

// fixture is one wired module plus the fakes behind it.
type fixture struct {
	t       *testing.T
	mgr     *Manager
	api     *API
	gw      *fakeGateway
	store   *FileStore
	blobs   *FileBlobStore
	sealer  *fakeSealer
	metrics *Metrics
	devices map[string]Device
	audits  []auditRec
	mu      sync.Mutex
	now     time.Time
	// principal is what Authz returns; tests swap it to change the caller.
	principal Principal
	authzOK   bool
	// gates records which gate each handler asked for.
	gates []Gate
}

type auditRec struct {
	Tenant string
	Action string
	Detail map[string]any
}

func newFixture(t *testing.T, tweak func(*Deps)) *fixture {
	t.Helper()
	dir := t.TempDir()
	sealer := &fakeSealer{active: true}
	blobs, err := NewFileBlobStore(dir+"/blobs", sealer.Marker())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	fx := &fixture{
		t: t, gw: &fakeGateway{payload: samplePCAP(3)},
		store: NewFileStore(dir + "/captures.json"), blobs: blobs, sealer: sealer,
		metrics: NewMetrics(), devices: map[string]Device{},
		now:       time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC),
		principal: Principal{Tenant: "acme", Subject: "a@acme"},
		authzOK:   true,
	}
	fx.devices["acme-core"] = Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1",
		Vendor: "cisco", OS: "NX-OS", TenantID: "acme"}
	fx.devices["globex-core"] = Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1",
		Vendor: "cisco", OS: "NX-OS", TenantID: "globex"}
	fx.devices["acme-iosxe"] = Device{ID: "acme-iosxe", Name: "acme-iosxe", Address: "10.1.0.2",
		Vendor: "cisco", OS: "IOS-XE", TenantID: "acme"}
	fx.devices["acme-mystery"] = Device{ID: "acme-mystery", Name: "acme-mystery", Address: "10.1.0.9",
		Vendor: "acme-networks", OS: "SomeOS", TenantID: "acme"}

	d := Deps{
		Now:          func() time.Time { return fx.now },
		LookupDevice: func(id string) (Device, bool) { dev, ok := fx.devices[id]; return dev, ok },
		Gateway:      fx.gw,
		Commands:     NewProfileCommandTable(),
		Sealer:       sealer,
		Blobs:        blobs,
		Store:        fx.store,
		Metrics:      fx.metrics,
		Authz: func(w http.ResponseWriter, _ *http.Request, gate Gate) (Principal, bool) {
			fx.gates = append(fx.gates, gate)
			if !fx.authzOK {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			return fx.principal, true
		},
		Audit: func(_ *http.Request, tenant, action string, detail map[string]any) {
			fx.mu.Lock()
			defer fx.mu.Unlock()
			fx.audits = append(fx.audits, auditRec{Tenant: tenant, Action: action, Detail: detail})
		},
		WriteJSON:  testWriteJSON,
		WriteError: testWriteError,
		LogWarn:    func(string, map[string]any) {},
		LogError:   func(string, map[string]any) {},
		Scrub:      func(s string) string { return s },
		Keep:       DefaultKeep,
		// Synchronous runner: the capture body completes before Start returns, so
		// assertions never race the goroutine.
		Run: func(fn func()) { fn() },
	}
	if tweak != nil {
		tweak(&d)
	}
	mgr, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fx.mgr = mgr
	fx.api = NewAPI(mgr)
	return fx
}

func (f *fixture) auditsFor(action string) []auditRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []auditRec{}
	for _, a := range f.audits {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// as switches the caller.
func (f *fixture) as(tenant string, cross bool) *fixture {
	f.principal = Principal{Tenant: tenant, Cross: cross, Subject: "u@" + tenant}
	return f
}

// do runs one request through the REAL subtree dispatcher.
func (f *fixture) do(method, path, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if !f.api.ServeDeviceSubroute(w, r) {
		f.t.Fatalf("the pcap subtree did not claim %s %s", method, path)
	}
	return w
}

func writeJSONBody(w io.Writer, body any) error {
	return json.NewEncoder(w).Encode(body)
}

func testWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = writeJSONBody(w, body)
}

func testWriteError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = writeJSONBody(w, map[string]string{"error": err.Error()})
}
