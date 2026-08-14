package backend

// quarantine_api_test.go — F-11 slice 4 (design doc D5): the operator
// quarantine workflow's security contract.
//
// Like the unseal endpoint this surface turns protected data back into
// plaintext (indirectly: it re-injects it into the normal pipeline), so the
// tests are about REFUSAL first: who is turned away, that the sealed payload
// never appears in a list response, and that the restore is replay-safe and
// audited.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/quarantine"
	"netops/backend/internal/rbac"
	"netops/backend/internal/secobs"
	"netops/backend/models"
)

const (
	quarListPath   = "/api/quarantine"
	quarReattrPath = "/api/quarantine/reattribute"
)

func f11Sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// quarFakeOS is a purpose-built OpenSearch stand-in: search replies come from
// the queue (last one repeats), DELETEs are recorded and acknowledged, _update
// calls (the flows replay-guard claim/rollback) are recorded with their query
// string and acknowledged — or 409'd when updateConflict is set.
type quarFakeOS struct {
	mu             sync.Mutex
	searches       []string // recorded search request bodies
	deletes        []string // recorded DELETE paths
	updates        []string // recorded _update "path?query|body" entries
	replies        []string // consumed one per search; last repeats
	updateConflict bool     // every _update answers 409 (lost CAS)
}

func newQuarFakeOS(t *testing.T, replies ...string) *quarFakeOS {
	t.Helper()
	f := &quarFakeOS{replies: replies}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodDelete:
			f.deletes = append(f.deletes, r.URL.Path)
			_, _ = w.Write([]byte(`{"result":"deleted"}`))
		case strings.HasSuffix(r.URL.Path, "/_search"):
			b, _ := io.ReadAll(r.Body)
			f.searches = append(f.searches, string(b))
			i := len(f.searches) - 1
			if i >= len(f.replies) {
				i = len(f.replies) - 1
			}
			_, _ = w.Write([]byte(f.replies[i]))
		case strings.Contains(r.URL.Path, "/_update/"):
			b, _ := io.ReadAll(r.Body)
			f.updates = append(f.updates, r.URL.Path+"?"+r.URL.RawQuery+"|"+string(b))
			if f.updateConflict {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"type":"version_conflict_engine_exception"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"result":"updated"}`))
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("OPENSEARCH_URL", srv.URL)
	return f
}

// quarBusRecorder captures bus-bridge produce envelopes.
type quarBusRecorder struct {
	mu        sync.Mutex
	envelopes []map[string]any
}

func newQuarBusRecorder(t *testing.T) *quarBusRecorder {
	t.Helper()
	rec := &quarBusRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envs []map[string]any
		if err := json.NewDecoder(r.Body).Decode(&envs); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.mu.Lock()
		rec.envelopes = append(rec.envelopes, envs...)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("BUS_BRIDGE_URL", srv.URL)
	return rec
}

func emptyQuarSearchReply() string {
	return `{"hits":{"total":{"value":0,"relation":"eq"},"hits":[]},"aggregations":{"oldest_received":{"value":null}}}`
}

// A tenant admin — even one whose role is the full super-admin grid inside its
// own tenant — must be refused on BOTH routes: quarantine holds other
// tenants' unattributed data by definition.
func TestQuarantineRoutesArePlatformOnly(t *testing.T) {
	osRec := newQuarFakeOS(t, emptyQuarSearchReply())
	ts, _, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	tenantID := createTenantFor(t, ts, admin, "quar-acme")
	tenantAdmin := createUserFor(t, ts, admin, "quar-tadmin", "admin", tenantID)

	if st, body := do(t, ts, "GET", quarListPath, tenantAdmin, nil); st != http.StatusForbidden {
		t.Fatalf("tenant admin listed the quarantine: %d %s", st, body)
	}
	if st, body := do(t, ts, "POST", quarReattrPath, tenantAdmin, map[string]any{"identity_sha": f11Sha("x")}); st != http.StatusForbidden {
		t.Fatalf("tenant admin reached reattribute: %d %s", st, body)
	}
	if n := len(osRec.searches) + len(osRec.deletes); n != 0 {
		t.Fatalf("a refused caller reached OpenSearch (%d requests)", n)
	}
}

// Reattribute is the unseal-equivalent capability: a platform-side admin
// WITHOUT sensitive_data:admin must be refused by that gate specifically.
func TestQuarantineReattributeRequiresSensitiveDataAdmin(t *testing.T) {
	newQuarFakeOS(t, emptyQuarSearchReply())
	ts, s, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token

	// A custom platform-side role WITHOUT sensitive_data:admin. (The built-in
	// super-admin short-circuits every permission check, and the role store
	// refuses custom roles holding administration:admin — so this is the only
	// caller shape that can make the sensitive_data gate itself visible. The
	// handler checks that gate FIRST, before the platform gate, precisely so
	// the refusal names the missing capability.)
	if _, err := s.roles.Upsert(rbac.Role{
		ID: "platform-lite", Name: "Platform Lite",
		Permissions: map[string]int{"administration": LevelRead},
	}); err != nil {
		t.Fatal(err)
	}
	st, b := do(t, ts, "POST", "/api/users", admin, map[string]any{
		"username": "quar-lite", "password": "Passw0rd!2345", "role": "platform-lite", "tenant_id": TenantGlobal,
	})
	if st != 201 {
		t.Fatalf("create platform-lite user: %d %s", st, b)
	}
	lite := login(t, ts, "quar-lite", "Passw0rd!2345").Token

	st, body := do(t, ts, "POST", quarReattrPath, lite, map[string]any{"identity_sha": f11Sha("x")})
	if st != http.StatusForbidden {
		t.Fatalf("want 403 without sensitive_data:admin, got %d %s", st, body)
	}
	if !strings.Contains(string(body), "sensitive_data") {
		t.Fatalf("refusal must come from the sensitive_data gate: %s", body)
	}
}

// Without sealing custody there is no quarantine stage and no key to unseal
// with — the endpoints must say so (501), not 404 or 500.
func TestQuarantineUnavailableWhenSealingOff(t *testing.T) {
	ts, s, _ := sealTestServer(t)
	s.sealProvider = nil
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	if st, _ := do(t, ts, "GET", quarListPath, admin, nil); st != http.StatusNotImplemented {
		t.Fatalf("list: want 501 when sealing is off, got %d", st)
	}
	if st, _ := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": f11Sha("x")}); st != http.StatusNotImplemented {
		t.Fatalf("reattribute: want 501 when sealing is off, got %d", st)
	}
}

// The list is metadata ONLY. Even when OpenSearch hands back the sealed
// payload in _source, it must not survive into the response.
func TestQuarantineListOmitsSealedPayload(t *testing.T) {
	reply := `{"hits":{"total":{"value":2,"relation":"eq"},"hits":[
	  {"_index":"netops-quarantine-2026.08.12","_id":"d1","_source":{
	    "cx_event_id":"e1","received_at":"2026-08-12T01:00:00Z","lane":"syslog",
	    "identity_sha":"` + f11Sha("edge-1") + `","source_ip":"10.0.0.9","reason":"TENANT_UNATTRIBUTABLE",
	    "cx_quarantine_payload":"<enc:v1:quarantine:1:aXY:Y3Q:bWFj>"}},
	  {"_index":"netops-quarantine-2026.08.11","_id":"d2","_source":{
	    "cx_event_id":"e2","received_at":"2026-08-11T01:00:00Z","lane":"flows",
	    "identity_sha":"bb","reason":"TENANT_UNATTRIBUTABLE",
	    "cx_quarantine_payload":"<enc:v1:quarantine:1:aXY:Y3Q:bWFj>"}}
	]},"aggregations":{"oldest_received":{"value":1754874000000,"value_as_string":"2026-08-11T01:00:00.000Z"}}}`
	newQuarFakeOS(t, reply)
	ts, _, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token

	req, err := http.NewRequest("GET", ts.URL+quarListPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
	s := string(body)
	if strings.Contains(s, "cx_quarantine_payload") || strings.Contains(s, "<enc:") {
		t.Fatalf("THE LIST LEAKED THE SEALED PAYLOAD: %s", s)
	}
	var out struct {
		Quarantine []map[string]any `json:"quarantine"`
		Summary    struct {
			Total            int64   `json:"total"`
			OldestReceivedAt *string `json:"oldest_received_at"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if len(out.Quarantine) != 2 {
		t.Fatalf("rows = %d, want 2", len(out.Quarantine))
	}
	first := out.Quarantine[0]
	for _, want := range []string{"cx_event_id", "received_at", "lane", "identity_sha", "reason", "_index"} {
		if _, okf := first[want]; !okf {
			t.Errorf("metadata field %q missing from list row: %v", want, first)
		}
	}
	if out.Summary.Total != 2 {
		t.Errorf("summary.total = %d, want 2", out.Summary.Total)
	}
	if out.Summary.OldestReceivedAt == nil || !strings.HasPrefix(*out.Summary.OldestReceivedAt, "2026-08-11") {
		t.Errorf("summary.oldest_received_at = %v", out.Summary.OldestReceivedAt)
	}
	if got := resp.Header.Get("X-Total-Count"); got != "2" {
		t.Errorf("X-Total-Count = %q, want 2 (the bounded-read contract)", got)
	}
}

// The full restore path: seal two events under the REAL quarantine context,
// reattribute them, and verify re-injection, tombstoning, auditing and
// replay-safety.
func TestQuarantineReattributeHappyPathAndReplay(t *testing.T) {
	ts, s, p := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	s.discovery.Upsert(models.Device{ID: "edge-1", Name: "edge-1", Address: "10.9.9.9", TenantID: "acme"})

	sha := f11Sha("edge-1")
	ctx := context.Background()
	seal := func(event map[string]any) string {
		t.Helper()
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := p.Seal(ctx, quarantine.SealContext(), string(raw))
		if err != nil {
			t.Fatalf("seal quarantine payload: %v", err)
		}
		return tok
	}
	tok1 := seal(map[string]any{"message": "one", "hostname": "edge-1", "tenant_id": "", "tenant_registry": "miss"})
	tok2 := seal(map[string]any{"message": "two", "hostname": "edge-1", "tenant_id": "", "tenant_registry": "miss"})

	firstReply := `{"hits":{"total":{"value":2,"relation":"eq"},"hits":[
	  {"_index":"netops-quarantine-2026.08.12","_id":"osd1","_source":{
	    "cx_event_id":"e1","received_at":"2026-08-12T01:00:00Z","lane":"syslog",
	    "identity_sha":"` + sha + `","reason":"TENANT_UNATTRIBUTABLE",
	    "cx_quarantine_payload":` + quarJSON(t, tok1) + `}},
	  {"_index":"netops-quarantine-2026.08.12","_id":"osd2","_source":{
	    "cx_event_id":"e2","received_at":"2026-08-12T01:05:00Z","lane":"syslog",
	    "identity_sha":"` + sha + `","reason":"TENANT_UNATTRIBUTABLE",
	    "cx_quarantine_payload":` + quarJSON(t, tok2) + `}}
	]},"aggregations":{}}`
	osRec := newQuarFakeOS(t, firstReply, emptyQuarSearchReply())
	bus := newQuarBusRecorder(t)

	st, body := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": sha})
	if st != http.StatusOK {
		t.Fatalf("reattribute: %d %s", st, body)
	}
	var out struct {
		MatchedIdentityCount int    `json:"matched_identity_count"`
		Tenant               string `json:"tenant"`
		Restored             int    `json:"restored"`
		Failed               int    `json:"failed"`
		Remaining            int    `json:"remaining"`
		Deleted              int    `json:"deleted"`
		DeleteFailed         int    `json:"delete_failed"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if out.Tenant != "acme" || out.MatchedIdentityCount != 1 {
		t.Errorf("resolution: %+v", out)
	}
	if out.Restored != 2 || out.Failed != 0 || out.Deleted != 2 || out.DeleteFailed != 0 || out.Remaining != 0 {
		t.Errorf("restore counts wrong: %+v", out)
	}

	// The bus received the two ORIGINAL events, tenant-stamped and idempotent.
	bus.mu.Lock()
	envs := append([]map[string]any(nil), bus.envelopes...)
	bus.mu.Unlock()
	if len(envs) != 2 {
		t.Fatalf("bus envelopes = %d, want 2", len(envs))
	}
	seenIDs := map[string]bool{}
	for _, env := range envs {
		if env["topic"] != "netops.syslog" {
			t.Errorf("topic = %v, want netops.syslog", env["topic"])
		}
		if env["key"] != "acme" {
			t.Errorf("key = %v, want acme", env["key"])
		}
		ev, oke := env["event"].(map[string]any)
		if !oke {
			t.Fatalf("event missing: %v", env)
		}
		if ev["tenant_id"] != "acme" {
			t.Errorf("re-injected tenant_id = %v", ev["tenant_id"])
		}
		if _, present := ev["tenant_registry"]; present {
			t.Error("tenant_registry survived — the event would re-quarantine")
		}
		if ev["cx_restored_from"] != "quarantine" {
			t.Errorf("cx_restored_from = %v", ev["cx_restored_from"])
		}
		id, _ := ev["cx_event_id"].(string)
		seenIDs[id] = true
	}
	if !seenIDs["e1"] || !seenIDs["e2"] {
		t.Errorf("cx_event_id not carried through (idempotency): %v", seenIDs)
	}

	// Both quarantine docs were tombstoned — in the quarantine index only.
	osRec.mu.Lock()
	dels := append([]string(nil), osRec.deletes...)
	osRec.mu.Unlock()
	if len(dels) != 2 {
		t.Fatalf("OS deletes = %v, want 2", dels)
	}
	for _, d := range dels {
		if !strings.HasPrefix(d, "/netops-quarantine-2026.08.12/_doc/") {
			t.Errorf("delete outside the quarantine index: %s", d)
		}
	}

	// The explicit audit record: the sec_event, the counts, and no payload.
	events, err := s.audit.List(TenantGlobal, true, auditQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.Path != quarReattrPath || e.Detail == nil || e.Detail[secobs.SecEventKey] != secobs.SecEventQuarantineRestore {
			continue
		}
		found = true
		if fmt.Sprint(e.Detail["restored"]) != "2" || fmt.Sprint(e.Detail["failed"]) != "0" {
			t.Errorf("audit counts wrong: %v", e.Detail)
		}
		if e.Detail["tenant"] != "acme" || e.Detail["identity_sha"] != sha {
			t.Errorf("audit detail wrong: %v", e.Detail)
		}
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), "<enc:") || strings.Contains(string(blob), `"message":"one"`) {
			t.Fatalf("THE AUDIT TRAIL RECORDED PAYLOAD MATERIAL: %s", blob)
		}
	}
	if !found {
		t.Fatal("no audit record with the quarantine_reattribute sec_event")
	}

	// Replay safety: the same call again finds nothing (the docs are gone) and
	// succeeds with zero work — it must not error and must not re-produce.
	st, body = do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": sha})
	if st != http.StatusOK {
		t.Fatalf("second call: %d %s", st, body)
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Restored != 0 || out.Failed != 0 || out.Deleted != 0 {
		t.Errorf("second call did work: %+v", out)
	}
	bus.mu.Lock()
	n := len(bus.envelopes)
	bus.mu.Unlock()
	if n != 2 {
		t.Errorf("second call re-produced events: %d envelopes", n)
	}
}

func TestQuarantineReattributeUnknownOrBadIdentity(t *testing.T) {
	osRec := newQuarFakeOS(t, emptyQuarSearchReply())
	ts, s, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	s.discovery.Upsert(models.Device{ID: "edge-1", Name: "edge-1", Address: "10.9.9.9", TenantID: "acme"})
	// Ambiguity at the identity-STRING level: acme's device address equals a
	// globex device's NAME. (Two devices sharing the same name would be merged
	// by the inventory's cross-source dedupe — identity tokens are typed, so
	// name-vs-address collisions are the ambiguity shape that survives it.)
	s.discovery.Upsert(models.Device{ID: "amb-a", Name: "amb-a", Address: "10.7.7.7", TenantID: "acme"})
	s.discovery.Upsert(models.Device{ID: "amb-b", Name: "10.7.7.7", Address: "10.8.8.8", TenantID: "globex"})

	// Unknown identity: 409, and OpenSearch is never consulted.
	st, body := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": f11Sha("never-seen")})
	if st != http.StatusConflict {
		t.Fatalf("unknown identity: want 409, got %d %s", st, body)
	}
	if !strings.Contains(string(body), "assign the device") {
		t.Errorf("unknown-identity error must tell the operator what to do: %s", body)
	}

	// Ambiguous identity (two tenants): 409.
	if st, body := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": f11Sha("10.7.7.7")}); st != http.StatusConflict {
		t.Fatalf("ambiguous identity: want 409, got %d %s", st, body)
	}

	// Malformed sha: 400, refused by name.
	if st, _ := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": "not-hex"}); st != http.StatusBadRequest {
		t.Fatalf("malformed sha: want 400, got %d", st)
	}
	if st, _ := do(t, ts, "POST", quarReattrPath, admin, map[string]any{}); st != http.StatusBadRequest {
		t.Fatalf("missing sha: want 400, got %d", st)
	}

	if n := len(osRec.searches) + len(osRec.deletes); n != 0 {
		t.Fatalf("a refused reattribution reached OpenSearch (%d requests)", n)
	}
}

func quarJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The flows lane's canonical store is ClickHouse (plain MergeTree — no id_key
// dedup), so its restore path must be guarded end to end: claim the envelope
// via CAS _update BEFORE the produce, refuse the replay of an already-claimed
// envelope, and stand down entirely on a lost CAS. This pins the handler
// wiring of quarantine.RestoreDeps.{Claim,Unclaim}.
func TestQuarantineReattributeFlowsReplayGuard(t *testing.T) {
	flowsReply := func(sha, tok, restoredAt string) string {
		restored := ""
		if restoredAt != "" {
			restored = `"cx_restored_at":"` + restoredAt + `",`
		}
		return `{"hits":{"total":{"value":1,"relation":"eq"},"hits":[
		  {"_index":"netops-quarantine-2026.08.14","_id":"fd1","_seq_no":7,"_primary_term":2,"_source":{
		    "cx_event_id":"fe1","received_at":"2026-08-14T01:00:00Z","lane":"flows",
		    ` + restored + `"identity_sha":"` + sha + `","reason":"TENANT_UNATTRIBUTABLE",
		    "cx_quarantine_payload":` + tok + `}}
		]},"aggregations":{}}`
	}
	newFlowsFixture := func(t *testing.T, restoredAt string) (*httptest.Server, string, *quarFakeOS, *quarBusRecorder, string) {
		t.Helper()
		ts, s, p := sealTestServer(t)
		admin := login(t, ts, "admin", "Passw0rd!2345").Token
		s.discovery.Upsert(models.Device{ID: "edge-9", Name: "edge-9", Address: "10.9.9.19", TenantID: "acme"})
		sha := f11Sha("edge-9")
		raw, err := json.Marshal(map[string]any{
			"src_addr": "10.1.1.1", "dst_addr": "10.2.2.2", "bytes": 42,
			"tenant_id": "", "tenant_registry": "miss",
		})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := p.Seal(context.Background(), quarantine.SealContext(), string(raw))
		if err != nil {
			t.Fatal(err)
		}
		osRec := newQuarFakeOS(t, flowsReply(sha, quarJSON(t, tok), restoredAt), emptyQuarSearchReply())
		bus := newQuarBusRecorder(t)
		return ts, admin, osRec, bus, sha
	}
	reattr := func(t *testing.T, ts *httptest.Server, admin, sha string) map[string]any {
		t.Helper()
		st, body := do(t, ts, "POST", quarReattrPath, admin, map[string]any{"identity_sha": sha})
		if st != http.StatusOK {
			t.Fatalf("reattribute: %d %s", st, body)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	busCount := func(b *quarBusRecorder) int {
		b.mu.Lock()
		defer b.mu.Unlock()
		return len(b.envelopes)
	}

	t.Run("happy path claims before producing", func(t *testing.T) {
		ts, admin, osRec, bus, sha := newFlowsFixture(t, "")
		out := reattr(t, ts, admin, sha)
		if out["restored"] != float64(1) || out["replay_refused"] != float64(0) || out["deleted"] != float64(1) {
			t.Fatalf("counts: %v", out)
		}
		if busCount(bus) != 1 {
			t.Fatalf("bus envelopes = %d, want 1", busCount(bus))
		}
		osRec.mu.Lock()
		updates := append([]string(nil), osRec.updates...)
		deletes := append([]string(nil), osRec.deletes...)
		osRec.mu.Unlock()
		if len(updates) != 1 {
			t.Fatalf("claim _update calls = %v, want exactly 1", updates)
		}
		u := updates[0]
		if !strings.HasPrefix(u, "/netops-quarantine-2026.08.14/_update/fd1?") {
			t.Errorf("claim update outside the quarantine envelope: %s", u)
		}
		if !strings.Contains(u, "if_seq_no=7") || !strings.Contains(u, "if_primary_term=2") {
			t.Errorf("claim is not a CAS on the search-time doc version: %s", u)
		}
		if !strings.Contains(u, "cx_restored_at") {
			t.Errorf("claim does not stamp cx_restored_at: %s", u)
		}
		if len(deletes) != 1 {
			t.Errorf("tombstone deletes = %v, want 1", deletes)
		}
	})

	t.Run("lost CAS produces nothing", func(t *testing.T) {
		ts, admin, osRec, bus, sha := newFlowsFixture(t, "")
		osRec.mu.Lock()
		osRec.updateConflict = true
		osRec.mu.Unlock()
		out := reattr(t, ts, admin, sha)
		if out["restored"] != float64(0) || out["replay_refused"] != float64(1) {
			t.Fatalf("counts: %v", out)
		}
		if busCount(bus) != 0 {
			t.Fatal("a flows event was produced after LOSING the claim CAS — duplicate canonical row")
		}
		osRec.mu.Lock()
		nDeletes := len(osRec.deletes)
		osRec.mu.Unlock()
		if nDeletes != 0 {
			t.Fatal("tombstoned an envelope owned by the concurrent claim winner")
		}
	})

	t.Run("already claimed envelope is never re-produced", func(t *testing.T) {
		ts, admin, osRec, bus, sha := newFlowsFixture(t, "2026-08-14T00:30:00Z")
		out := reattr(t, ts, admin, sha)
		if out["restored"] != float64(0) || out["replay_refused"] != float64(1) || out["deleted"] != float64(1) {
			t.Fatalf("counts: %v", out)
		}
		if busCount(bus) != 0 {
			t.Fatal("an already-claimed flows envelope was produced AGAIN — duplicate canonical row")
		}
		osRec.mu.Lock()
		nUpdates, nDeletes := len(osRec.updates), len(osRec.deletes)
		osRec.mu.Unlock()
		if nUpdates != 0 {
			t.Error("no claim update expected for an envelope that already carries the stamp")
		}
		if nDeletes != 1 {
			t.Error("the lingering tombstone was not retried")
		}
	})
}
