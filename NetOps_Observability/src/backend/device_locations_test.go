package backend

// device_locations_test.go — adversarial/robustness tests for the geomap
// location annotation layer: boundary + hostile input at the HTTP boundary,
// tenant isolation, identity drift, concurrency (race detector target), and
// store durability across reloads.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

func locServer(t *testing.T) *server {
	t.Helper()
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	dir := t.TempDir()
	dl, err := newDeviceLocationStore(dir + "/device_locations.json")
	if err != nil {
		t.Fatal(err)
	}
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{discovery: d, deviceLocations: dl, roles: roles}
}

func TestDeviceLocationHostileInput(t *testing.T) {
	s := locServer(t)
	put := func(id, body string) int {
		w := httptest.NewRecorder()
		s.handleDeviceLocation(w, req("PUT", "/api/devices/"+id+"/location", body, superA()))
		return w.Code
	}

	cases := []struct {
		name string
		id   string
		body string
		want int
	}{
		{"valid", "acme-core", `{"site":"HQ","lat":32.78,"lng":-96.80}`, 200},
		{"boundary north pole", "acme-core", `{"lat":90,"lng":180}`, 200},
		{"boundary south", "acme-core", `{"lat":-90,"lng":-180}`, 200},
		{"lat overflow", "acme-core", `{"lat":90.0001,"lng":0}`, 400},
		{"lng overflow", "acme-core", `{"lat":0,"lng":-180.0001}`, 400},
		{"NaN rejected by JSON", "acme-core", `{"lat":NaN,"lng":0}`, 400},
		{"bad json", "acme-core", `{"lat":`, 400},
		{"site label too long", "acme-core", fmt.Sprintf(`{"site":%q,"lat":1,"lng":1}`, strings.Repeat("x", 121)), 400},
		{"oversized body", "acme-core", `{"site":"` + strings.Repeat("a", 8<<10) + `","lat":1,"lng":1}`, 400},
		{"unknown device", "ghost", `{"lat":1,"lng":1}`, 404},
		{"path traversal id", "../../etc/passwd", `{"lat":1,"lng":1}`, 404},
		{"empty id", "", `{"lat":1,"lng":1}`, 404},
	}
	for _, c := range cases {
		if got := put(c.id, c.body); got != c.want {
			t.Errorf("%s: PUT %q -> %d, want %d", c.name, c.id, got, c.want)
		}
	}

	// Hostile-but-legal site label is stored as inert data (output encoding is
	// the frontend's job; the API must neither crash nor mangle it).
	xss := `<img src=x onerror=alert(1)>`
	if got := put("acme-core", fmt.Sprintf(`{"site":%q,"lat":1,"lng":1}`, xss)); got != 200 {
		t.Fatalf("xss-label PUT -> %d", got)
	}
	w := httptest.NewRecorder()
	s.handleDeviceLocation(w, req("GET", "/api/devices/acme-core/location", "", superA()))
	var resp struct {
		Set      bool           `json:"set"`
		Location DeviceLocation `json:"location"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || !resp.Set {
		t.Fatalf("GET after PUT: err=%v set=%v", err, resp.Set)
	}
	if resp.Location.Site != xss {
		t.Fatalf("site label mangled: %q", resp.Location.Site)
	}
}

// Tenant isolation: a scoped principal can neither read nor write another
// tenant's device placement, and learns nothing about the id's existence.
func TestDeviceLocationTenantIsolation(t *testing.T) {
	s := locServer(t)
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		w := httptest.NewRecorder()
		s.handleDeviceLocation(w, req(method, "/api/devices/globex-core/location", `{"lat":1,"lng":1}`, acme()))
		if w.Code != 404 {
			t.Errorf("%s foreign-tenant device -> %d, want 404 (no existence leak)", method, w.Code)
		}
	}
	// And the editor list never includes the foreign device.
	w := httptest.NewRecorder()
	s.handleDeviceLocations(w, req("GET", "/api/devices/locations", "", acme()))
	if strings.Contains(w.Body.String(), "globex-core") {
		t.Fatal("locations editor leaked a foreign tenant's device")
	}
}

// Read-only principals must not be able to mutate placement (SR-003 parity
// with the other device routes).
func TestDeviceLocationWriteNeedsWritePerm(t *testing.T) {
	s := locServer(t)
	ro := jwtClaims{Sub: "viewer", Role: "viewer", Tenant: "acme"}
	w := httptest.NewRecorder()
	s.handleDeviceLocation(w, req("PUT", "/api/devices/acme-core/location", `{"lat":1,"lng":1}`, ro))
	if w.Code != 403 {
		t.Fatalf("read-only PUT -> %d, want 403", w.Code)
	}
	w = httptest.NewRecorder()
	s.handleDeviceLocation(w, req("GET", "/api/devices/acme-core/location", "", ro))
	if w.Code != 200 {
		t.Fatalf("read-only GET -> %d, want 200", w.Code)
	}
}

// Identity drift: when a device's primary identity changes between saves, the
// re-save must not leave a stale duplicate reachable via the old token.
func TestDeviceLocationIdentityDrift(t *testing.T) {
	dl, err := newDeviceLocationStore(t.TempDir() + "/loc.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := dl.Upsert([]string{"ip:10.0.0.1", "name:leaf1"}, DeviceLocation{Lat: 1, Lng: 1}); err != nil {
		t.Fatal(err)
	}
	// Device re-discovered with a new mgmt IP; same name.
	if err := dl.Upsert([]string{"ip:10.9.9.9", "name:leaf1"}, DeviceLocation{Lat: 2, Lng: 2}); err != nil {
		t.Fatal(err)
	}
	if _, ok := dl.Lookup([]string{"ip:10.0.0.1"}); ok {
		t.Fatal("stale entry survives under the old identity token")
	}
	if l, ok := dl.Lookup([]string{"name:leaf1"}); !ok || l.Lat != 2 {
		t.Fatalf("drifted device lost its placement: %+v ok=%v", l, ok)
	}
}

// Durability: the store round-trips through its file across a restart.
func TestDeviceLocationPersistence(t *testing.T) {
	path := t.TempDir() + "/loc.json"
	dl, _ := newDeviceLocationStore(path)
	if err := dl.Upsert([]string{"ip:10.0.0.1"}, DeviceLocation{Site: "HQ", Lat: 1.5, Lng: -2.5}); err != nil {
		t.Fatal(err)
	}
	dl2, err := newDeviceLocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	l, ok := dl2.Lookup([]string{"ip:10.0.0.1"})
	if !ok || l.Site != "HQ" || l.Lat != 1.5 {
		t.Fatalf("placement lost across restart: %+v ok=%v", l, ok)
	}
}

// Concurrency: hammer the store from parallel writers/readers/deleters — the
// race detector (CI gate) turns any unsynchronized access into a failure.
func TestDeviceLocationConcurrency(t *testing.T) {
	dl, _ := newDeviceLocationStore(t.TempDir() + "/loc.json")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(3)
		tok := fmt.Sprintf("ip:10.0.0.%d", i%4)
		go func(tok string, i int) {
			defer wg.Done()
			_ = dl.Upsert([]string{tok}, DeviceLocation{Lat: float64(i % 90), Lng: float64(i % 180)})
		}(tok, i)
		go func(tok string) {
			defer wg.Done()
			dl.Lookup([]string{tok})
			dl.Empty()
		}(tok)
		go func(tok string) {
			defer wg.Done()
			_ = dl.Delete([]string{tok})
		}(tok)
	}
	wg.Wait()
}
