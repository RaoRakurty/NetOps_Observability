package dem

// http_test.go — the module's boundary. The properties under test are the ones
// the page depends on being true: an unmeasured window is HONEST (a reason, not
// an empty table), a cross-tenant principal is refused, a foreign id is a 404,
// and the owner is stamped from the token.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type apiHarness struct {
	api   *API
	cat   Catalogue
	q     *fakeQuerier
	princ Principal
	gates []Gate
}

func newAPIHarness(t *testing.T, enabled bool, withMetrics bool) *apiHarness {
	t.Helper()
	h := &apiHarness{cat: NewFileStore(""), princ: Principal{Tenant: "acme", Subject: "u1"}}
	if withMetrics {
		h.q = &fakeQuerier{rows: map[string][]Sample{}}
	}
	var q Querier
	if h.q != nil {
		q = h.q
	}
	api, err := NewAPI(APIDeps{
		Authz: func(_ http.ResponseWriter, _ *http.Request, g Gate) (Principal, bool) {
			h.gates = append(h.gates, g)
			return h.princ, true
		},
		Targets: h.cat, Metrics: q, Enabled: enabled,
		Now: func() time.Time { return time.Unix(1_757_000_000, 0).UTC() },
		WriteJSON: func(w http.ResponseWriter, s int, b any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(s)
			_ = json.NewEncoder(w).Encode(b)
		},
		WriteError: func(w http.ResponseWriter, s int, e error) { w.WriteHeader(s); _, _ = w.Write([]byte(e.Error())) },
		LogWarn:    func(string, map[string]any) {},
	})
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	h.api = api
	return h
}

func TestNewAPIFailsClosedOnIncompleteDeps(t *testing.T) {
	if _, err := NewAPI(APIDeps{}); err == nil {
		t.Fatal("an API with no authz and no store was built — it would read unscoped")
	}
}

func (h *apiHarness) call(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	}
	w := httptest.NewRecorder()
	switch {
	case strings.HasPrefix(path, ExperiencePath):
		h.api.HandleExperience(w, r)
	case strings.HasPrefix(path, TargetItemPath) && len(path) > len(TargetItemPath):
		h.api.HandleTargetItem(w, r)
	default:
		h.api.HandleTargets(w, r)
	}
	return w.Code, w.Body.String()
}

func TestCreateStampsTheOwnerFromTheToken(t *testing.T) {
	h := newAPIHarness(t, true, false)
	// The wire type has no tenant field at all, so a tenant claim cannot even
	// be expressed — and an unknown field is refused rather than dropped.
	code, body := h.call(t, http.MethodPost, TargetsPath,
		`{"name":"portal","kind":"http","host":"https://portal.example/","tenant_id":"globex"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("a tenant claim in the body was accepted: %d %s", code, body)
	}
	code, body = h.call(t, http.MethodPost, TargetsPath,
		`{"name":"portal","kind":"http","host":"https://portal.example/","site":"dc1"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var got Target
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.TenantID != "acme" || got.CreatedBy != "u1" {
		t.Fatalf("owner not stamped from the token: %+v", got)
	}
}

func TestCrossTenantPrincipalIsRefused(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.princ = Principal{Tenant: TenantGlobalSentinel, Cross: true, Subject: "owner"}
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, TargetsPath, ""},
		{http.MethodPost, TargetsPath, `{"name":"x","kind":"icmp","host":"10.0.0.1"}`},
		{http.MethodGet, ExperiencePath, ""},
	} {
		code, body := h.call(t, tc.method, tc.path, tc.body)
		if code != http.StatusBadRequest {
			t.Fatalf("%s %s: cross-tenant principal got %d %s", tc.method, tc.path, code, body)
		}
	}
}

func TestForeignAndMalformedIdsAre404(t *testing.T) {
	h := newAPIHarness(t, true, false)
	other := mustCreate(t, h.cat, newTarget("globex", "theirs", "10.0.0.9"))
	for _, id := range []string{other.ID, "dem-zzzz", "../../etc/passwd", "dem-"} {
		code, _ := h.call(t, http.MethodGet, TargetItemPath+id, "")
		if code != http.StatusNotFound {
			t.Fatalf("GET %q → %d (want 404: an id must never be confirmed to exist)", id, code)
		}
	}
	code, _ := h.call(t, http.MethodDelete, TargetItemPath+other.ID, "")
	if code != http.StatusNotFound {
		t.Fatalf("cross-tenant DELETE → %d", code)
	}
	if _, err := h.cat.Get(context.Background(), "globex", other.ID); err != nil {
		t.Fatalf("the victim's row was destroyed: %v", err)
	}
}

func TestWriteGateIsUsedForWrites(t *testing.T) {
	h := newAPIHarness(t, true, false)
	h.call(t, http.MethodGet, TargetsPath, "")
	h.call(t, http.MethodPost, TargetsPath, `{"name":"x","kind":"icmp","host":"10.0.0.1"}`)
	if len(h.gates) != 2 || h.gates[0] != GateRead || h.gates[1] != GateWrite {
		t.Fatalf("gates used: %v", h.gates)
	}
}

func TestUnknownQueryParameterIsRefusedButAsTenantIsNot(t *testing.T) {
	h := newAPIHarness(t, true, false)
	if code, _ := h.call(t, http.MethodGet, TargetsPath+"?filter=all", ""); code != http.StatusBadRequest {
		t.Fatalf("an unknown query parameter was ignored: %d", code)
	}
	// as_tenant is the platform switcher; it can only narrow and is applied
	// upstream, so the handler must not reject it.
	if code, _ := h.call(t, http.MethodGet, TargetsPath+"?as_tenant=acme", ""); code != http.StatusOK {
		t.Fatalf("as_tenant was rejected: %d", code)
	}
}

// The four honest not-measured shapes. NONE of them may be an empty table.
func TestExperienceIsHonestWhenNothingWasMeasured(t *testing.T) {
	t.Run("feature off", func(t *testing.T) {
		h := newAPIHarness(t, false, true)
		mustCreate(t, h.cat, newTarget("acme", "spine1", "10.0.0.1"))
		var resp ExperienceResponse
		code, body := h.call(t, http.MethodGet, ExperiencePath, "")
		mustJSON(t, code, body, &resp)
		if resp.Enabled || resp.Measured || resp.Reason != ReasonFeatureOff || resp.Note == "" {
			t.Fatalf("%+v", resp)
		}
		if len(resp.Targets) != 1 || resp.Targets[0].Measured {
			t.Fatalf("a declared target was dropped or scored: %+v", resp.Targets)
		}
	})
	t.Run("no targets", func(t *testing.T) {
		h := newAPIHarness(t, true, true)
		var resp ExperienceResponse
		code, body := h.call(t, http.MethodGet, ExperiencePath, "")
		mustJSON(t, code, body, &resp)
		if resp.Measured || resp.Reason != ReasonNoTargets || resp.Note == "" {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("no metrics backend", func(t *testing.T) {
		h := newAPIHarness(t, true, false)
		mustCreate(t, h.cat, newTarget("acme", "spine1", "10.0.0.1"))
		var resp ExperienceResponse
		code, body := h.call(t, http.MethodGet, ExperiencePath, "")
		mustJSON(t, code, body, &resp)
		if resp.Measured || resp.Reason != ReasonQueryFailed {
			t.Fatalf("%+v", resp)
		}
	})
	t.Run("metrics store did not answer", func(t *testing.T) {
		h := newAPIHarness(t, true, true)
		h.q.err = errUpstream
		mustCreate(t, h.cat, newTarget("acme", "spine1", "10.0.0.1"))
		var resp ExperienceResponse
		code, body := h.call(t, http.MethodGet, ExperiencePath, "")
		mustJSON(t, code, body, &resp)
		if resp.Measured || resp.Reason != ReasonQueryFailed {
			t.Fatalf("a failed query rendered as %+v", resp)
		}
		if strings.Contains(strings.ToLower(resp.Note), "healthy") && !strings.Contains(resp.Note, "not a healthy") {
			t.Fatalf("note reads as health: %q", resp.Note)
		}
	})
	t.Run("prober reporting nothing", func(t *testing.T) {
		h := newAPIHarness(t, true, true)
		mustCreate(t, h.cat, newTarget("acme", "spine1", "10.0.0.1"))
		var resp ExperienceResponse
		code, body := h.call(t, http.MethodGet, ExperiencePath, "")
		mustJSON(t, code, body, &resp)
		if resp.Measured || resp.Reason != ReasonNoProber {
			t.Fatalf("%+v", resp)
		}
		if len(resp.Targets) != 1 || resp.Targets[0].Score != nil {
			t.Fatalf("an unmeasured target carried a score: %+v", resp.Targets)
		}
	})
}

func TestExperienceScoresAndRollsUp(t *testing.T) {
	h := newAPIHarness(t, true, true)
	tgt := mustCreate(t, h.cat, Target{
		TenantID: "acme", Name: "portal", Kind: KindHTTP, Host: "https://portal.example/",
		Site: "dc1", App: "portal", LatencyBudgetMs: 500, AvailabilityBudgetPct: 99,
	})
	lbl := map[string]string{"target": tgt.ID}
	h.q.rows = map[string][]Sample{
		"count_over_time(dem_probe_success":    {{Labels: lbl, Value: 60}},
		"sum_over_time(dem_probe_success":      {{Labels: lbl, Value: 60}},
		"count_over_time(dem_probe_latency_ms": {{Labels: lbl, Value: 60}},
		"quantile_over_time(0.50":              {{Labels: lbl, Value: 120}},
		"quantile_over_time(0.95":              {{Labels: lbl, Value: 200}},
	}
	var resp ExperienceResponse
	code, body := h.call(t, http.MethodGet, ExperiencePath+"?window=24h", "")
	mustJSON(t, code, body, &resp)
	if resp.Window != Window24h || !resp.Measured || resp.ScoredCount != 1 {
		t.Fatalf("%+v", resp)
	}
	if len(resp.Targets) != 1 || resp.Targets[0].Score == nil || *resp.Targets[0].Score != 100 {
		t.Fatalf("target score: %+v", resp.Targets)
	}
	if len(resp.Sites) != 1 || resp.Sites[0].Key != "dc1" || resp.Sites[0].Scope != "site" {
		t.Fatalf("site rollup: %+v", resp.Sites)
	}
	if len(resp.Apps) != 1 || resp.Apps[0].Key != "portal" {
		t.Fatalf("app rollup: %+v", resp.Apps)
	}
	if resp.Targets[0].Site != "dc1" || resp.Targets[0].Source != SourceSynthetic {
		t.Fatalf("identity not carried onto the result: %+v", resp.Targets[0].Identity)
	}
}

func TestExperienceRefusesAnUnknownWindow(t *testing.T) {
	h := newAPIHarness(t, true, true)
	if code, _ := h.call(t, http.MethodGet, ExperiencePath+"?window=30d", ""); code != http.StatusBadRequest {
		t.Fatalf("window=30d → %d", code)
	}
}

func TestMethodsAreBounded(t *testing.T) {
	h := newAPIHarness(t, true, true)
	if code, _ := h.call(t, http.MethodPatch, TargetsPath, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("PATCH collection → %d", code)
	}
	if code, _ := h.call(t, http.MethodPost, ExperiencePath, ""); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST experience → %d", code)
	}
}

// TenantGlobalSentinel mirrors the integrator's platform-tenant token. The
// module must treat it as scopeless rather than as a shared bucket.
const TenantGlobalSentinel = ""

var errUpstream = &upstreamErr{}

type upstreamErr struct{}

func (*upstreamErr) Error() string { return "upstream refused" }

func mustJSON(t *testing.T, code int, body string, into any) {
	t.Helper()
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), into); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
}
