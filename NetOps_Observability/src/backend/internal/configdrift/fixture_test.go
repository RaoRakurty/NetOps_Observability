// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configdrift

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/configstore"
)

// fixture_test.go — the in-package harness. Everything external is injected, so
// the evaluator, the state machine and the bus emission run with no store
// backend, no bus and no HTTP server.

// canaries are the strings that must NEVER appear on the bus or in a log: the
// configuration itself, and a secret inside it.
const (
	canaryConfigLine = "ip address 10.77.77.77 255.255.255.0"
	canarySecret     = "S3cr3tEnablePw-drift"
)

func cfgText(marker string) string {
	return "hostname " + marker + "\n" +
		"enable secret 5 " + canarySecret + "\n" +
		"interface Gi0/0\n " + canaryConfigLine + "\n"
}

// fakeSealer/fakeBlobs give the ConfigSource test a real store to read through.
type memBlobs struct {
	mu   sync.Mutex
	rows map[string]string
}

func newMemBlobs() *memBlobs { return &memBlobs{rows: map[string]string{}} }

func (m *memBlobs) Put(tenant, deviceID, sha, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, "seal:") {
		return "", errors.New("unsealed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := tenant + "/" + deviceID + "/" + sha
	m.rows[ref] = sealed
	return ref, nil
}

func (m *memBlobs) Get(ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.rows[ref]
	if !ok {
		return "", configstore.ErrNotFound
	}
	return v, nil
}

func (m *memBlobs) Delete(ref string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, ref)
	return nil
}

func seal(plaintext string) string {
	return "seal:" + base64.StdEncoding.EncodeToString([]byte(plaintext))
}

func unseal(sealed string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, "seal:"))
	return string(b), err
}

// fakeBus records what was published instead of reaching a broker.
type fakeBus struct {
	mu        sync.Mutex
	published [][]Record
	topics    []string
	err       error
	calls     int
}

func (b *fakeBus) Publish(_ context.Context, topic string, recs []Record) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return 0, b.err
	}
	b.topics = append(b.topics, topic)
	cp := append([]Record(nil), recs...)
	b.published = append(b.published, cp)
	return len(recs), nil
}

func (b *fakeBus) records() []Record {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []Record{}
	for _, batch := range b.published {
		out = append(out, batch...)
	}
	return out
}

type fixture struct {
	t     *testing.T
	eval  *Evaluator
	store *FileStore
	vers  *configstore.FileStore
	blobs *memBlobs
	bus   *fakeBus

	principal Principal
	authzOK   bool
	spooled   []Record
	spoolErr  error
	now       time.Time
	mu        sync.Mutex
}

func newFixture(t *testing.T, tune func(*Deps)) *fixture {
	t.Helper()
	f := &fixture{
		t: t, store: NewFileStore(""), vers: configstore.NewFileStore(""),
		blobs: newMemBlobs(), bus: &fakeBus{}, authzOK: true,
		now: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
	}
	d := Deps{
		Now:      func() time.Time { return f.now },
		Store:    f.store,
		Versions: f.vers,
		Open: func(v configstore.Version) (string, error) {
			sealed, err := f.blobs.Get(v.BlobRef)
			if err != nil {
				return "", err
			}
			return unseal(sealed)
		},
		Publish: f.bus.Publish,
		Spool: func(_ string, recs []Record, _ error) error {
			if f.spoolErr != nil {
				return f.spoolErr
			}
			f.mu.Lock()
			f.spooled = append(f.spooled, recs...)
			f.mu.Unlock()
			return nil
		},
		Devices: func(tenant string) []DeviceRef {
			if tenant == "acme" {
				return []DeviceRef{{ID: "d1", Name: "acme-edge-01", TenantID: "acme"}}
			}
			return nil
		},
		Metrics: NewMetrics(),
		Authz: func(w http.ResponseWriter, _ *http.Request, _ Gate) (Principal, bool) {
			if !f.authzOK {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			return f.principal, true
		},
		WriteJSON:  testWriteJSON,
		WriteError: testWriteError,
		LogWarn:    func(string, map[string]any) {},
		LogError:   func(string, map[string]any) {},
		Scrub:      func(s string) string { return s },
	}
	if tune != nil {
		tune(&d)
	}
	e, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.eval = e
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

// event builds a CaptureEvent the evaluator can classify.
func event(tenant, deviceID, current string) configstore.CaptureEvent {
	return configstore.CaptureEvent{
		Device: configstore.Device{ID: deviceID, Name: deviceID + "-name",
			Address: "10.0.0.9", Vendor: "Cisco IOS-XE", TenantID: tenant},
		Tenant: tenant, Vendor: configstore.VendorCisco,
		CapturedAt: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC),
		SHA:        configstore.SHA256Hex(current), Current: current,
	}
}

func withPrevious(ev configstore.CaptureEvent, prev string) configstore.CaptureEvent {
	ev.HasPrevious, ev.Previous, ev.PreviousSHA = true, prev, configstore.SHA256Hex(prev)
	return ev
}

func withGolden(ev configstore.CaptureEvent, golden string) configstore.CaptureEvent {
	ev.HasGolden, ev.Golden, ev.GoldenSHA = true, golden, configstore.SHA256Hex(golden)
	return ev
}

func (f *fixture) do(method, path string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	f.eval.HandleDriftList(w, r)
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
