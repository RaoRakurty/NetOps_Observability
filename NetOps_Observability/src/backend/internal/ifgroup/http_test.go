package ifgroup

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// http_test.go — the HTTP surface: parameter refusal, the 404 parity that keeps
// the route from being an existence oracle, the fail-closed metrics boundary,
// and the honest states.

type fixture struct {
	api      *API
	queries  []string
	filters  [][]string
	vmErr    map[string]error // query substring → error
	devices  map[string]Device
	canSee   func(Device, Principal) bool
	scope    []string
	authOK   bool
	samples  map[string][]Sample // query substring → rows
	vendorOK bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		devices: map[string]Device{
			"core-1": {ID: "core-1", Name: "core-1.acme", Vendor: "juniper", TenantID: "acme"},
		},
		canSee:  func(Device, Principal) bool { return true },
		scope:   []string{`{device=~"core-1"}`},
		authOK:  true,
		samples: map[string][]Sample{},
		vmErr:   map[string]error{},
	}
	api, err := New(Deps{
		Authz: func(w http.ResponseWriter, _ *http.Request, _ Gate) (Principal, bool) {
			if !f.authOK {
				http.Error(w, "forbidden", http.StatusForbidden)
				return Principal{}, false
			}
			return Principal{Tenant: "acme", Subject: "u@acme"}, true
		},
		LookupDevice: func(id string) (Device, bool) { d, ok := f.devices[id]; return d, ok },
		CanSee:       func(d Device, p Principal) bool { return f.canSee(d, p) },
		ScopeFilters: func(*http.Request, Principal) []string { return f.scope },
		VMQuery: func(_ context.Context, q string, filters []string) ([]Sample, error) {
			f.queries = append(f.queries, q)
			f.filters = append(f.filters, append([]string(nil), filters...))
			for frag, err := range f.vmErr {
				if strings.Contains(q, frag) {
					return nil, err
				}
			}
			for frag, rows := range f.samples {
				if strings.Contains(q, frag) {
					return rows, nil
				}
			}
			return nil, nil
		},
		VRFTerm:   func(string) (string, bool) { return "routing-instance", f.vendorOK },
		WriteJSON: func(w http.ResponseWriter, status int, body any) { writeJSON(w, status, body) },
		WriteError: func(w http.ResponseWriter, status int, err error) {
			writeJSON(w, status, map[string]string{"error": err.Error()})
		},
		LogWarn: func(string, map[string]any) {},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.api = api
	return f
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fixture) get(path string) *httptest.ResponseRecorder {
	f.queries, f.filters = nil, nil
	w := httptest.NewRecorder()
	f.api.Handler()(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

func (f *fixture) decode(t *testing.T, w *httptest.ResponseRecorder) Response {
	t.Helper()
	var out Response
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return out
}

const route = "/api/devices/core-1/interfaces/by-vrf"

// ── Deps validation ─────────────────────────────────────────────────────────

func TestNewRefusesAnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{WriteJSON: writeJSON}); err == nil {
		t.Fatal("New accepted a Deps with no Authz/CanSee/VMQuery — the module must fail closed at construction")
	} else if !strings.Contains(err.Error(), "Authz") || !strings.Contains(err.Error(), "ScopeFilters") {
		t.Errorf("the error must name what is missing, got %q", err)
	}
}

func TestNilAPIAnswers404(t *testing.T) {
	w := httptest.NewRecorder()
	(*API)(nil).Handler()(w, httptest.NewRequest(http.MethodGet, route, nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("a nil API must 404, got %d", w.Code)
	}
}

// ── routing ─────────────────────────────────────────────────────────────────

func TestDeviceIDFromPath(t *testing.T) {
	if id, ok := deviceIDFromPath(route); !ok || id != "core-1" {
		t.Errorf("deviceIDFromPath = %q/%v, want core-1/true", id, ok)
	}
	for _, bad := range []string{
		"/api/devices/interfaces/by-vrf",      // empty id
		"/api/devices/a/b/interfaces/by-vrf",  // id with a separator
		"/api/devices/core-1/interfaces",      // wrong suffix
		"/api/devices/core-1/pcap",            // another subtree
		"/api/other/core-1/interfaces/by-vrf", // wrong prefix
	} {
		if _, ok := deviceIDFromPath(bad); ok {
			t.Errorf("deviceIDFromPath(%q) accepted a path it does not serve", bad)
		}
	}
}

func TestNonGETIsRefused(t *testing.T) {
	f := newFixture(t)
	w := httptest.NewRecorder()
	f.api.Handler()(w, httptest.NewRequest(http.MethodPost, route, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Errorf("POST = %d Allow=%q, want 405/GET", w.Code, w.Header().Get("Allow"))
	}
}

// ── parameters (fail closed) ────────────────────────────────────────────────

func TestUnknownQueryParameterIsRefused(t *testing.T) {
	f := newFixture(t)
	w := f.get(route + "?vrf=CORP-WAN")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown parameter = %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if len(f.queries) != 0 {
		t.Error("a refused request must not reach the metric store")
	}
}

func TestWindowIsBoundedAndNeverSilentlySubstituted(t *testing.T) {
	f := newFixture(t)
	for _, bad := range []string{"30d", "1s", "banana", "-5m", "48h"} {
		w := f.get(route + "?window=" + bad)
		if w.Code != http.StatusBadRequest {
			t.Errorf("window=%s = %d, want 400 — a caller who asked for it must be told, not handed a default", bad, w.Code)
		}
	}
	w := f.get(route + "?window=1h")
	if w.Code != http.StatusOK {
		t.Fatalf("window=1h = %d (%s)", w.Code, w.Body.String())
	}
	if got := f.decode(t, w).Window; got != "1h" {
		t.Errorf("echoed window = %q, want 1h", got)
	}
	if !strings.Contains(strings.Join(f.queries, " "), "[1h]") {
		t.Errorf("the window did not reach the rate queries: %v", f.queries)
	}
	// The default is applied only when nothing was asked for.
	w = f.get(route)
	if got := f.decode(t, w).Window; got != "5m" {
		t.Errorf("default window = %q, want 5m", got)
	}
}

func TestPromDurationRendersWholeUnits(t *testing.T) {
	cases := map[time.Duration]string{
		5 * time.Minute: "5m", time.Hour: "1h", 24 * time.Hour: "24h", 90 * time.Second: "90s",
	}
	for d, want := range cases {
		if got := promDuration(d); got != want {
			t.Errorf("promDuration(%s) = %q, want %q", d, got, want)
		}
	}
}

// ── device resolution / isolation ───────────────────────────────────────────

func TestForeignDeviceIsIndistinguishableFromAnAbsentOne(t *testing.T) {
	f := newFixture(t)
	f.devices["globex-core"] = Device{ID: "globex-core", Name: "gx-edge", TenantID: "globex"}
	f.canSee = func(d Device, p Principal) bool { return d.TenantID == p.Tenant }

	foreign := f.get("/api/devices/globex-core/interfaces/by-vrf")
	foreignBody, foreignQueries := foreign.Body.String(), len(f.queries)
	absent := f.get("/api/devices/no-such-device/interfaces/by-vrf")

	if foreign.Code != http.StatusNotFound || absent.Code != http.StatusNotFound {
		t.Fatalf("foreign=%d absent=%d, want 404/404", foreign.Code, absent.Code)
	}
	if foreignBody != absent.Body.String() {
		t.Errorf("EXISTENCE ORACLE: foreign %q != absent %q", foreignBody, absent.Body.String())
	}
	if strings.Contains(foreignBody, "globex") || strings.Contains(foreignBody, "gx-edge") {
		t.Errorf("the 404 leaked the foreign device: %s", foreignBody)
	}
	if foreignQueries != 0 {
		t.Error("a device the caller cannot see must not reach the metric store")
	}
}

func TestEveryMetricsReadCarriesTheCallersBoundary(t *testing.T) {
	f := newFixture(t)
	if w := f.get(route); w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s)", w.Code, w.Body.String())
	}
	if len(f.queries) == 0 {
		t.Fatal("no metrics read was issued")
	}
	for i, q := range f.queries {
		if len(f.filters[i]) == 0 {
			t.Errorf("UNSCOPED metrics read: %q", q)
		}
		if !strings.Contains(q, `device=~"core-1|core-1\\.acme"`) {
			t.Errorf("query %q does not select the resolved device on BOTH identity labels", q)
		}
	}
}

// A scoped principal with no device boundary is REFUSED, never served the fleet.
func TestScopedPrincipalWithNoBoundaryIsRefused(t *testing.T) {
	f := newFixture(t)
	f.scope = nil
	w := f.get(route)
	if w.Code != http.StatusForbidden {
		t.Fatalf("scopeless read = %d, want 403 (%s)", w.Code, w.Body.String())
	}
	if len(f.queries) != 0 {
		t.Error("the fleet was queried for a principal with no boundary")
	}
	if !strings.Contains(w.Body.String(), "device filter") {
		t.Errorf("the refusal must name the reason, got %s", w.Body.String())
	}
}

func TestUnauthorizedCallerNeverReachesTheStore(t *testing.T) {
	f := newFixture(t)
	f.authOK = false
	if w := f.get(route); w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized = %d, want 403", w.Code)
	}
	if len(f.queries) != 0 {
		t.Error("an unauthorized request reached the metric store")
	}
}

// ── honest states ───────────────────────────────────────────────────────────

// The device has no interface series at all: "not collected", explained — not
// an empty page and not a zeroed dashboard.
func TestNoSeriesIsReportedAsNotCollected(t *testing.T) {
	f := newFixture(t)
	w := f.get(route)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s)", w.Code, w.Body.String())
	}
	got := f.decode(t, w)
	if got.Coverage.Interfaces != 0 || len(got.Groups) != 0 {
		t.Errorf("expected no interfaces and no groups, got %+v", got.Coverage)
	}
	if got.Coverage.Transport != TransportNone {
		t.Errorf("transport = %q, want %q", got.Coverage.Transport, TransportNone)
	}
	if len(got.Coverage.Notes) == 0 {
		t.Error("an empty answer must carry the reason")
	}
}

// The state series fails: that is an ERROR, not "nothing is collected". This is
// the failure mode that would otherwise render a healthy-looking blank.
func TestAStateReadFailureIsAnErrorNotAnEmptyPage(t *testing.T) {
	f := newFixture(t)
	f.vmErr["device_if_oper_status"] = errors.New("upstream down")
	w := f.get(route)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("state read failure = %d, want 502 (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "upstream down") {
		t.Error("the upstream error text must not be echoed to the caller")
	}
}

// An ENRICHMENT failure degrades the fields it feeds to null and says so; it
// must not blank the page and must not become zeros.
func TestAnEnrichmentFailureDegradesToNullAndSaysSo(t *testing.T) {
	f := newFixture(t)
	f.samples["device_if_oper_status"] = []Sample{sample(1, "ifName", "ge-0/0/0")}
	f.vmErr["device_if_in_errors"] = errors.New("boom")
	w := f.get(route)
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s)", w.Code, w.Body.String())
	}
	got := f.decode(t, w)
	if got.Coverage.Interfaces != 1 {
		t.Fatalf("the page must still render its interfaces, got %+v", got.Coverage)
	}
	if got.Coverage.Errors {
		t.Error("a failed error-counter read must not be reported as covered")
	}
	if !strings.Contains(strings.Join(got.Coverage.Notes, " "), "device_if_in_errors") {
		t.Errorf("the degraded series must be named in the notes: %v", got.Coverage.Notes)
	}
	if got.Groups[0].Members[0].InErrPerS != nil {
		t.Error("a failed read must leave the field null, not zero")
	}
}

// The whole point of the feature, end to end: today's telemetry carries no vrf
// label, so the response groups nothing and says why, in the device's dialect.
func TestUngroupedAnswerUsesTheDeviceDialectAndClaimsNoDefault(t *testing.T) {
	f := newFixture(t)
	f.vendorOK = true
	f.samples["device_if_oper_status"] = []Sample{
		sample(1, "ifName", "ge-0/0/0"),
		sample(2, "ifName", "ge-0/0/1"),
	}
	f.samples["device_bgp_peer_state"] = []Sample{sample(6, "vrf", "CORP-WAN", "peer", "10.0.0.1")}

	got := f.decode(t, f.get(route))
	if got.Dialect.Term != "routing-instance" || got.Dialect.TermPlural != "Routing instances" {
		t.Errorf("dialect = %+v, want the Juniper words", got.Dialect)
	}
	if !got.Dialect.VendorKnown {
		t.Error("the vendor was claimed by a profile; vendor_known must say so")
	}
	if got.Coverage.VRFLabels {
		t.Error("no interface series carried a vrf label; coverage must say false")
	}
	if len(got.Groups) != 1 || got.Groups[0].VRF != "" || got.Groups[0].Membership != MembershipNotCollected {
		t.Fatalf("want one ungrouped bucket, got %+v", got.Groups)
	}
	if !strings.Contains(got.Groups[0].Label, "routing-instance") {
		t.Errorf("the bucket label must use the device's word, got %q", got.Groups[0].Label)
	}
	if strings.Contains(strings.ToLower(w2s(got)), "\"vrf\":\"default\"") {
		t.Error("the response invented a default instance")
	}
	// The instances the control plane DOES report are surfaced, without any
	// claim about interface membership.
	if len(got.RoutingInstances) != 1 || got.RoutingInstances[0].Name != "CORP-WAN" {
		t.Fatalf("known instances = %+v, want CORP-WAN", got.RoutingInstances)
	}
	if !strings.Contains(strings.Join(got.Coverage.Notes, " "), "routing_instances") {
		t.Errorf("the notes must point at the instance list: %v", got.Coverage.Notes)
	}
}

// An unrecognized vendor renders the majority default WITHOUT claiming the
// device was identified.
func TestUnknownVendorIsNotPresentedAsIdentified(t *testing.T) {
	f := newFixture(t)
	f.vendorOK = false
	got := f.decode(t, f.get(route))
	if got.Dialect.VendorKnown {
		t.Error("no profile claimed the vendor; vendor_known must be false")
	}
}

func w2s(r Response) string {
	b, _ := json.Marshal(r)
	return string(b)
}
