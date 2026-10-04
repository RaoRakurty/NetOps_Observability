// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_chip_edit_isolation_test.go — POST /api/ai/conversations/{id}/edits
// (tracker 337 N-C7 editable chips, N-C8 chip edits as corrections).
//
// Pinned: an answered turn carries chips built from the SERVER-held query; a
// chip edit regenerates the query server-side, validates it like a compiled
// one and runs it as a new turn of the same conversation; the client can
// never send a query (a forged AST is a 400) nor a value the server did not
// offer; a stale answer is refused; a valid edit is filed as a wrong_filter
// correction carrying the regenerated query on the caller's own record; and
// (§3a) a conversation, its chips and its corrections never cross tenants —
// another tenant, a colleague and an as_tenant walk get the same 404 as an
// unknown id, and another tenant's entity is never offered nor accepted.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/irisconvo"
	"netops/backend/internal/irisquerylog"
	"netops/backend/models"
)

type chipFixture struct {
	s     *server
	a, b  jwtClaims
	mu    sync.Mutex
	reads []string // extra_filters of every VictoriaMetrics read
}

func newChipFixture(t *testing.T) *chipFixture {
	t.Helper()
	f := &chipFixture{}
	t.Setenv("FEATURE_AI", "true")
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reads = append(f.reads, strings.Join(r.URL.Query()["extra_filters[]"], " "))
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"]]}]}}`))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
	f.s, f.a, f.b = nlqAPIFixture(t)
	f.s.nlqConvos = irisconvo.NewMemStore()
	f.s.nlqQueryLog = irisquerylog.NewMemStore()
	f.s.nlqQueryLogMetrics = irisquerylog.NewMetrics()
	if err := f.s.discovery.Upsert(models.Device{ID: "dev-a2", Name: "edge-a2", TenantID: "t-a", Labels: map[string]string{"site": "aus-br"}}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *chipFixture) readCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reads)
}

func editChip(t *testing.T, s *server, c jwtClaims, id string, body any) (int, map[string]any) {
	t.Helper()
	raw, ok := body.(string)
	if !ok {
		b, _ := json.Marshal(body)
		raw = string(b)
	}
	return convoCall(t, s, c, http.MethodPost, "/api/ai/conversations/"+id+"/edits", raw)
}

func chipsOf(t *testing.T, out map[string]any) []map[string]any {
	t.Helper()
	raw, _ := out["chips"].([]any)
	var cs []map[string]any
	for _, c := range raw {
		cs = append(cs, c.(map[string]any))
	}
	return cs
}

func findChip(cs []map[string]any, id string) map[string]any {
	for _, c := range cs {
		if c["id"] == id {
			return c
		}
	}
	return nil
}

func TestAChipEditRegeneratesValidatesAndRunsTheQuery(t *testing.T) {
	f := newChipFixture(t)
	id := startConvo(t, f.s, f.a)
	code, out := ask(t, f.s, f.a, id, "show cpu on edge-a for the last hour")
	if code != 200 || out["result"] == nil {
		t.Fatalf("first answer: %d %v", code, out)
	}
	cs := chipsOf(t, out)
	dev := findChip(cs, "ref:0")
	if dev == nil || dev["value"] != "device:dev-a" || findChip(cs, "window") == nil || findChip(cs, "metric") == nil {
		t.Fatalf("an answer carries its chips: %v", cs)
	}
	if raw := nlqJSON(dev["options"]); !strings.Contains(raw, "device:dev-a2") || strings.Contains(raw, "dev-b") {
		t.Fatalf("device options must be the caller's own devices only: %s", raw)
	}
	base, _ := out["chips_for"].(string)
	firstLog, _ := out["query_log_id"].(string)
	if len(base) != 64 || firstLog == "" {
		t.Fatalf("chips_for / query_log_id missing: %v", out)
	}

	before := f.readCount()
	code, out = editChip(t, f.s, f.a, id, map[string]string{"base": base, "chip": "ref:0", "op": "set", "value": "device:dev-a2"})
	if code != 200 || out["result"] == nil {
		t.Fatalf("chip edit: %d %v", code, out)
	}
	if ast := nlqJSON(out["ast"]); !strings.Contains(ast, "device:dev-a2") || strings.Contains(ast, `"device:dev-a"`) {
		t.Fatalf("the regenerated query must name the chosen device only: %s", ast)
	}
	if v, _ := out["validation"].(map[string]any); v["valid"] != true {
		t.Fatalf("the regenerated query must have been validated: %v", out["validation"])
	}
	if f.readCount() == before {
		t.Fatal("the regenerated query must run")
	}
	turn, _ := out["turn"].(map[string]any)
	if turn["edited"] != true || turn["outcome"] != "answered" || !strings.Contains(turn["question"].(string), "edge-a2") {
		t.Fatalf("the edit is a turn of the same conversation: %v", turn)
	}
	if out["conversation_id"] != id || out["chips_for"] == base {
		t.Fatalf("the edit answers in the same conversation with new chips: %v", out)
	}

	// N-C8: filed as a wrong_filter correction on the record it edited,
	// carrying the regenerated query.
	if out["correction"] != "recorded" {
		t.Fatalf("correction: %v", out["correction"])
	}
	tenant, _ := principalTenant(f.a)
	rec, err := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, firstLog)
	if err != nil || len(rec.Corrections) != 1 {
		t.Fatalf("record %v corrections %+v", err, rec.Corrections)
	}
	cor := rec.Corrections[0]
	if cor.Kind != irisquerylog.KindWrongFilter || cor.CorrectedAST == nil || !strings.Contains(nlqJSON(cor.CorrectedAST), "device:dev-a2") || cor.CorrectedHash == "" {
		t.Fatalf("the correction must carry the regenerated query: %+v", cor)
	}
	// The edit's own answer is recorded too, authored chip_edit.
	editRec, err := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, out["query_log_id"].(string))
	if err != nil || editRec.CompiledBy != irisquerylog.CompiledByChipEdit || editRec.Source != irisquerylog.SourceConversation || editRec.ConversationID != id {
		t.Fatalf("edit record: %v %+v", err, editRec)
	}

	// A second edit corrects the edit's own record (the latest answer).
	base2, _ := out["chips_for"].(string)
	code, out = editChip(t, f.s, f.a, id, map[string]string{"base": base2, "chip": "window", "op": "set", "value": "24h"})
	if code != 200 || !strings.Contains(nlqJSON(out["ast"]), `"last":"24h"`) || out["correction"] != "recorded" {
		t.Fatalf("window edit: %d %v", code, out)
	}
	if again, _ := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, editRec.ID); len(again.Corrections) != 1 {
		t.Fatalf("the second edit belongs to the first edit's record: %+v", again.Corrections)
	}
}

func TestAChipEditNeverTakesAQueryOrAnUnofferedValue(t *testing.T) {
	f := newChipFixture(t)
	id := startConvo(t, f.s, f.a)
	_, out := ask(t, f.s, f.a, id, "show cpu on edge-a for the last hour")
	base, _ := out["chips_for"].(string)
	before := f.readCount()
	forged := `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:dev-b"}],"time_range":{"kind":"relative","last":"1h"}}`
	for name, tc := range map[string]struct {
		body string
		want int
	}{
		"forged AST":            {`{"base":"` + base + `","chip":"ref:0","op":"set","value":"device:dev-a2","ast":` + forged + `}`, 400},
		"forged AST only":       {`{"ast":` + forged + `}`, 400},
		"state":                 {`{"base":"` + base + `","chip":"ref:0","op":"set","value":"device:dev-a2","state":{}}`, 400},
		"tenant":                {`{"base":"` + base + `","chip":"ref:0","op":"set","value":"device:dev-a2","tenant":"t-b"}`, 400},
		"foreign device":        {`{"base":"` + base + `","chip":"ref:0","op":"set","value":"device:dev-b"}`, 400},
		"free-text value":       {`{"base":"` + base + `","chip":"window","op":"set","value":"9999d"}`, 400},
		"unknown chip":          {`{"base":"` + base + `","chip":"ref:7","op":"set","value":"device:dev-a2"}`, 400},
		"required chip removed": {`{"base":"` + base + `","chip":"metric","op":"remove"}`, 400},
		"bad op":                {`{"base":"` + base + `","chip":"ref:0","op":"drop"}`, 400},
		"no base":               {`{"chip":"ref:0","op":"remove"}`, 400},
		"stale base":            {`{"base":"` + strings.Repeat("0", 64) + `","chip":"ref:0","op":"remove"}`, 409},
	} {
		if code, out := editChip(t, f.s, f.a, id, tc.body); code != tc.want {
			t.Errorf("%s: %d %v, want %d", name, code, out, tc.want)
		}
	}
	if f.readCount() != before {
		t.Fatal("a refused edit must never reach VictoriaMetrics")
	}
	// Nothing was appended for a refused edit.
	_, got := convoCall(t, f.s, f.a, http.MethodGet, "/api/ai/conversations/"+id, "")
	if n := len(got["turns"].([]any)); n != 1 {
		t.Fatalf("refused edits must not become turns: %d", n)
	}
	// Nothing to edit before an answer.
	id2 := startConvo(t, f.s, f.a)
	if code, _ := editChip(t, f.s, f.a, id2, map[string]string{"base": base, "chip": "ref:0", "op": "remove"}); code != http.StatusConflict {
		t.Fatalf("an edit with no answer to edit: %d, want 409", code)
	}
}

// The held query is not trusted either: when it names an entity the caller
// can no longer see (it left their scope; a tampered state row), the
// regenerated query is refused by the VALIDATOR — the same check a compiled
// question gets — and nothing runs or is filed as a correction. An entity the
// caller can no longer see is not offered as a choice in the first place.
func TestARegeneratedQueryIsValidatedInTheCurrentScope(t *testing.T) {
	f := newChipFixture(t)
	id := startConvo(t, f.s, f.a)
	if _, out := ask(t, f.s, f.a, id, "show cpu on edge-a2 for the last hour"); out["result"] == nil {
		t.Fatalf("seed edge-a2 into the conversation: %v", out)
	}
	_, out := ask(t, f.s, f.a, id, "show cpu on edge-a2 for the last hour")
	base, _ := out["chips_for"].(string)
	firstLog, _ := out["query_log_id"].(string)
	if err := f.s.discovery.Delete("dev-a2"); err != nil {
		t.Fatal(err)
	}
	if code, _ := editChip(t, f.s, f.a, id, map[string]string{"base": base, "chip": "ref:0", "op": "set", "value": "device:dev-a2"}); code != http.StatusBadRequest {
		t.Fatalf("an entity the caller can no longer see is not offered: %d", code)
	}
	before := f.readCount()
	code, out := editChip(t, f.s, f.a, id, map[string]string{"base": base, "chip": "window", "op": "set", "value": "24h"})
	if code != 200 || out["result"] != nil || !strings.Contains(nlqJSON(out["validation"]), "unknown_entity") {
		t.Fatalf("a held query naming a vanished entity must be unknown_entity, not run: %d %v", code, out)
	}
	if turn, _ := out["turn"].(map[string]any); turn["outcome"] != "invalid" {
		t.Fatalf("turn: %v", out["turn"])
	}
	if f.readCount() != before || out["correction"] != nil {
		t.Fatalf("an invalid regeneration must not run nor be filed: %v", out["correction"])
	}
	tenant, _ := principalTenant(f.a)
	if rec, _ := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, firstLog); len(rec.Corrections) != 0 {
		t.Fatalf("no correction for an invalid edit: %+v", rec.Corrections)
	}
	// The state is unchanged: the same answer is still the one to edit.
	if code, _ := editChip(t, f.s, f.a, id, map[string]string{"base": base, "chip": "window", "op": "set", "value": "6h"}); code != 200 {
		t.Fatalf("an invalid edit leaves the last answer editable: %d", code)
	}
}

// §3a: a conversation's chips and corrections are its owner's alone.
func TestChipEditsNeverCrossTenants(t *testing.T) {
	f := newChipFixture(t)
	id := startConvo(t, f.s, f.a)
	_, out := ask(t, f.s, f.a, id, "show cpu on edge-a for the last hour")
	base, _ := out["chips_for"].(string)
	firstLog, _ := out["query_log_id"].(string)
	colleague := f.a
	colleague.Sub = "ua-colleague"
	walker := f.b
	walker.ActingTenant = f.a.Tenant
	edit := map[string]string{"base": base, "chip": "window", "op": "set", "value": "24h"}
	for name, c := range map[string]jwtClaims{"other tenant": f.b, "same-tenant colleague": colleague, "as_tenant walk": walker} {
		code, _ := convoCall(t, f.s, c, http.MethodPost, "/api/ai/conversations/"+id+"/edits?as_tenant="+f.a.Tenant, nlqJSON(edit))
		if code != http.StatusNotFound {
			t.Errorf("%s edit: %d, want 404", name, code)
		}
	}
	// Indistinguishable from an id that never existed.
	if code, _ := editChip(t, f.s, f.b, "11111111-2222-4333-8444-555555555555", edit); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
	tenant, _ := principalTenant(f.a)
	if rec, _ := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, firstLog); len(rec.Corrections) != 0 {
		t.Fatalf("a refused foreign edit must not correct the owner's record: %+v", rec.Corrections)
	}

	// Tenant B's own conversation offers only tenant B's devices, and an id
	// of tenant A's is not accepted there.
	idB := startConvo(t, f.s, f.b)
	_, outB := ask(t, f.s, f.b, idB, "show cpu on edge-b for the last hour")
	devB := findChip(chipsOf(t, outB), "ref:0")
	if devB == nil || strings.Contains(nlqJSON(devB), "dev-a") {
		t.Fatalf("tenant B's chips must not offer tenant A's devices: %v", devB)
	}
	baseB, _ := outB["chips_for"].(string)
	if code, _ := editChip(t, f.s, f.b, idB, map[string]string{"base": baseB, "chip": "ref:0", "op": "set", "value": "device:dev-a"}); code != http.StatusBadRequest {
		t.Fatalf("tenant A's device as tenant B's value: %d, want 400", code)
	}
	// Tenant A's base is not a key into tenant B's conversation.
	if code, _ := editChip(t, f.s, f.b, idB, edit); code != http.StatusConflict {
		t.Fatalf("another conversation's base: %d, want 409", code)
	}
	// The owner's conversation is intact and still editable.
	if code, _ := editChip(t, f.s, f.a, id, edit); code != 200 {
		t.Fatalf("owner edit: %d", code)
	}
	if rec, _ := f.s.nlqQueryLog.Get(context.Background(), tenant, f.a.Sub, firstLog); len(rec.Corrections) != 1 {
		t.Fatalf("the owner's edit is filed on the owner's record: %+v", rec.Corrections)
	}
	tenantB, _ := principalTenant(f.b)
	recsB, _ := f.s.nlqQueryLog.List(context.Background(), tenantB, irisquerylog.ListFilter{})
	for _, r := range recsB {
		if len(r.Corrections) != 0 || r.ConversationID == id {
			t.Fatalf("tenant B's log holds tenant A's edit: %+v", r)
		}
	}
}

func TestChipEditRouteIsGated(t *testing.T) {
	f := newChipFixture(t)
	id := startConvo(t, f.s, f.a)
	if code, _ := convoCall(t, f.s, f.a, http.MethodGet, "/api/ai/conversations/"+id+"/edits", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET edits: %d, want 405", code)
	}
	t.Setenv("FEATURE_AI", "false")
	if code, _ := editChip(t, f.s, f.a, id, `{}`); code != http.StatusServiceUnavailable {
		t.Errorf("AI disabled: %d, want 503", code)
	}
}
