// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srcauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestMemStoreIsPerTenant(t *testing.T) {
	ctx := context.Background()
	st := NewMemStore()
	rev := []Class{ClassManual, ClassDeclared, ClassDiscovered, ClassController}
	if _, err := st.Put(ctx, "acme", "alice", rev); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Get(ctx, "globex"); ok {
		t.Fatal("tenant globex read tenant acme's order")
	}
	p, ok, err := st.Get(ctx, "acme")
	if err != nil || !ok || p.Order[0] != ClassManual || p.UpdatedBy != "alice" {
		t.Fatalf("acme: %+v %v %v", p, ok, err)
	}
	p.Order[0] = ClassController // the caller's copy only
	if q, _, _ := st.Get(ctx, "acme"); q.Order[0] != ClassManual {
		t.Fatal("Get must return a copy")
	}
	if err := st.Delete(ctx, "globex"); err != nil {
		t.Fatal("deleting a missing policy is not an error")
	}
	if _, ok, _ := st.Get(ctx, "acme"); !ok {
		t.Fatal("globex's delete removed acme's order")
	}
	if err := st.Delete(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := st.Get(ctx, "acme"); ok {
		t.Fatal("delete did not reset")
	}
	for _, bad := range []struct{ tenant, actor string }{{"", "a"}, {"acme", ""}, {" ", "a"}} {
		if _, err := st.Put(ctx, bad.tenant, bad.actor, rev); err == nil {
			t.Errorf("Put(%q,%q) accepted", bad.tenant, bad.actor)
		}
	}
	if _, err := st.Put(ctx, "acme", "alice", []Class{ClassManual}); !errors.Is(err, ErrInvalidOrder) {
		t.Fatalf("an invalid order must be refused by the store: %v", err)
	}
	if _, _, err := st.Get(ctx, ""); err == nil {
		t.Fatal("an empty tenant must never read")
	}
}

func TestMemStoreConcurrentPuts(t *testing.T) {
	st := NewMemStore()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			o := DefaultOrder()
			if i%2 == 0 {
				o = []Class{ClassManual, ClassController, ClassDiscovered, ClassDeclared}
			}
			if _, err := st.Put(context.Background(), "acme", "u", o); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	p, ok, _ := st.Get(context.Background(), "acme")
	if !ok || ValidateOrder(p.Order) != nil {
		t.Fatalf("after concurrent writes the stored order must be one whole valid order: %+v", p)
	}
}

type failStore struct{ Store }

func (failStore) Get(context.Context, string) (Policy, bool, error) {
	return Policy{}, false, errors.New("db down")
}

type corruptStore struct{ Store }

func (corruptStore) Get(context.Context, string) (Policy, bool, error) {
	return Policy{Order: []Class{ClassManual, ClassManual}}, true, nil
}

func TestEffectiveIsDefaultClosed(t *testing.T) {
	ctx := context.Background()
	if o, c, err := Effective(ctx, nil, "acme"); !IsDefault(o) || c || err != nil {
		t.Fatal("nil store → platform default, no error")
	}
	st := NewMemStore()
	if o, c, err := Effective(ctx, st, "acme"); !IsDefault(o) || c || err != nil {
		t.Fatal("no row → platform default")
	}
	if o, c, err := Effective(ctx, st, ""); !IsDefault(o) || c || err != nil {
		t.Fatal("no tenant → platform default, no store read")
	}
	rev := []Class{ClassManual, ClassDeclared, ClassDiscovered, ClassController}
	if _, err := st.Put(ctx, "acme", "a", rev); err != nil {
		t.Fatal(err)
	}
	if o, c, err := Effective(ctx, st, "acme"); o[0] != ClassManual || !c || err != nil {
		t.Fatalf("own order: %v %v %v", o, c, err)
	}
	if _, err := st.Put(ctx, "acme", "a", DefaultOrder()); err != nil {
		t.Fatal(err)
	}
	if _, c, _ := Effective(ctx, st, "acme"); c {
		t.Fatal("a stored order equal to the default is not 'customised'")
	}
	if o, c, err := Effective(ctx, failStore{}, "acme"); !IsDefault(o) || c || err == nil {
		t.Fatal("a failed read → platform default AND the error, never silent")
	}
	if o, _, err := Effective(ctx, corruptStore{}, "acme"); !IsDefault(o) || err == nil {
		t.Fatal("a stored order that no longer validates → platform default AND an error")
	}
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

type httpFix struct {
	deps   Deps
	audits []map[string]any
	caller Caller
	denied bool
	level  Level
}

func newHTTPFix(st Store) *httpFix {
	f := &httpFix{caller: Caller{Tenant: "acme", Sub: "alice"}}
	f.deps = Deps{
		Store: st,
		Authorize: func(w http.ResponseWriter, _ *http.Request, level Level) (Caller, bool) {
			f.level = level
			if f.denied {
				w.WriteHeader(http.StatusForbidden)
				return Caller{}, false
			}
			return f.caller, true
		},
		Audit: func(_ *http.Request, _ Caller, d map[string]any) { f.audits = append(f.audits, d) },
		WriteJSON: func(w http.ResponseWriter, status int, v any) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(v)
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		},
	}
	return f
}

func (f *httpFix) do(method, path, body string) (int, map[string]any) {
	r := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	f.deps.Handler(w, r)
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m
}

func orderOf(m map[string]any) []string {
	var out []string
	for _, e := range m["order"].([]any) {
		out = append(out, e.(map[string]any)["class"].(string))
	}
	return out
}

func TestHTTPLifecycle(t *testing.T) {
	f := newHTTPFix(NewMemStore())
	code, m := f.do(http.MethodGet, "/api/ai/source-authority", "")
	if code != 200 || m["customized"] != false || m["editable"] != true || strings.Join(orderOf(m), ",") != "controller,discovered,declared,manual" {
		t.Fatalf("GET default: %d %v", code, m)
	}
	if f.level != LevelRead {
		t.Fatal("GET must ask for read")
	}
	code, m = f.do(http.MethodPut, "/api/ai/source-authority", `{"order":["discovered","controller","declared","manual"]}`)
	if code != 200 || m["customized"] != true || orderOf(m)[0] != "discovered" || m["updated_by"] != "alice" {
		t.Fatalf("PUT: %d %v", code, m)
	}
	if f.level != LevelChange {
		t.Fatal("PUT must ask for change")
	}
	if len(f.audits) != 1 || f.audits[0]["action"] != "set" ||
		strings.Join(f.audits[0]["from"].([]string), ",") != "controller,discovered,declared,manual" ||
		strings.Join(f.audits[0]["to"].([]string), ",") != "discovered,controller,declared,manual" {
		t.Fatalf("audit: %v", f.audits)
	}
	if _, m = f.do(http.MethodGet, "/api/ai/source-authority", ""); orderOf(m)[0] != "discovered" {
		t.Fatalf("GET after PUT: %v", m)
	}
	code, m = f.do(http.MethodDelete, "/api/ai/source-authority", "")
	if code != 200 || m["customized"] != false || orderOf(m)[0] != "controller" {
		t.Fatalf("DELETE: %d %v", code, m)
	}
	if len(f.audits) != 2 || f.audits[1]["action"] != "reset" || f.audits[1]["from"].([]string)[0] != "discovered" {
		t.Fatalf("reset audit: %v", f.audits)
	}
}

func TestHTTPRefusals(t *testing.T) {
	f := newHTTPFix(NewMemStore())
	for _, c := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"smuggled tenant", http.MethodPut, "/api/ai/source-authority", `{"order":["controller","discovered","declared","manual"],"tenant_id":"globex"}`, 400},
		{"not a permutation", http.MethodPut, "/api/ai/source-authority", `{"order":["controller","controller","declared","manual"]}`, 400},
		{"unknown class", http.MethodPut, "/api/ai/source-authority", `{"order":["controller","discovered","declared","model_inference"]}`, 400},
		{"empty", http.MethodPut, "/api/ai/source-authority", `{}`, 400},
		{"not json", http.MethodPut, "/api/ai/source-authority", `controller`, 400},
		{"oversized", http.MethodPut, "/api/ai/source-authority", `{"order":["` + strings.Repeat("x", 5000) + `"]}`, 400},
		{"sub-path", http.MethodGet, "/api/ai/source-authority/globex", "", 404},
		{"method", http.MethodPost, "/api/ai/source-authority", "", 405},
	} {
		if code, m := f.do(c.method, c.path, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.name, code, m, c.want)
		}
	}
	if len(f.audits) != 0 {
		t.Fatalf("a refused change must not be audited as a change: %v", f.audits)
	}
	if p, ok, _ := f.deps.Store.Get(context.Background(), "acme"); ok {
		t.Fatalf("a refused change was stored: %+v", p)
	}

	f.caller = Caller{Tenant: "global", Cross: true, Sub: "root"} // principalTenant's real Global view: a tenant string AND cross
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if code, _ := f.do(m, "/api/ai/source-authority", `{"order":["controller","discovered","declared","manual"]}`); code != 400 {
			t.Errorf("Global view %s: %d, want 400 (choose a workspace)", m, code)
		}
	}
	f.caller = Caller{Tenant: "acme", Sub: "alice"}
	f.denied = true
	if code, _ := f.do(http.MethodPut, "/api/ai/source-authority", `{"order":["controller","discovered","declared","manual"]}`); code != 403 {
		t.Fatalf("Authorize refusal must stand: %d", code)
	}
}

func TestHTTPWithoutStore(t *testing.T) {
	f := newHTTPFix(nil)
	code, m := f.do(http.MethodGet, "/api/ai/source-authority", "")
	if code != 200 || m["editable"] != false || orderOf(m)[0] != "controller" {
		t.Fatalf("GET without a store answers the platform default: %d %v", code, m)
	}
	for _, meth := range []string{http.MethodPut, http.MethodDelete} {
		if code, _ := f.do(meth, "/api/ai/source-authority", `{"order":["controller","discovered","declared","manual"]}`); code != http.StatusServiceUnavailable {
			t.Errorf("%s without a store: %d, want 503", meth, code)
		}
	}
}

func TestHTTPStoreFailureIsA500NotADefault(t *testing.T) {
	f := newHTTPFix(failStore{NewMemStore()})
	var logged int
	f.deps.Log = func(string, error) { logged++ }
	if code, _ := f.do(http.MethodGet, "/api/ai/source-authority", ""); code != 500 || logged != 1 {
		t.Fatalf("a failed read must be a logged 500, never a confident default: %d logged=%d", code, logged)
	}
}

func TestMetrics(t *testing.T) {
	var nilM *Metrics
	nilM.Observe(Resolution{})
	nilM.PolicyError()
	if err := nilM.Write(&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	m := &Metrics{}
	one := claim(ClassController, "api:x", "c", "a", t0)
	m.Observe(Resolution{Considered: []Claim{one}})
	m.Observe(Resolution{Considered: []Claim{one, one}})
	m.Observe(Resolution{Considered: []Claim{one, one}, Disagreements: []Claim{one}})
	m.PolicyError()
	var b bytes.Buffer
	if err := m.Write(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`outcome="agreed"} 1`, `outcome="disagreed"} 1`, `outcome="single_source"} 1`, `outcome="policy_error"} 1`} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("metrics lack %s:\n%s", want, b.String())
		}
	}
}
