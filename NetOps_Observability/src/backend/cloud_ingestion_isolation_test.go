// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_ingestion_isolation_test.go — CROSS-ORG isolation for the metric-store
// half of GET /api/cloud/ingestion (CLAUDE.md §3a rule 5), through the real router
// + auth middleware, against a fake VictoriaMetrics that evaluates the selector it
// is sent. The fake holds every tenant's series, so a response can only be clean
// because the selector was: an unscoped read returns the other tenant's provider
// and counts, as the real store would.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/cloud"
)

const (
	ingAcmeVM    = "i-acme1"
	ingGlobexVM  = "i-globex1"
	ingGlobexARM = "/subscriptions/globex-sub/resourceGroups/rg.prod/providers/Microsoft.Compute/virtualMachines/globex-db-1"
)

// ingFakeSeries is one cloud_* series the fake store holds.
type ingFakeSeries struct{ provider, resourceID string }

// ingFakeVM evaluates the two proof queries against a fixed series set, honouring
// the resource_id matcher exactly as VictoriaMetrics would: anchored, after
// PromQL string unescaping. No matcher means every series.
type ingFakeVM struct {
	mu      sync.Mutex
	queries []string
	status  int
}

var ingResourceMatcher = regexp.MustCompile(`resource_id=~"((?:[^"\\]|\\.)*)"`)

func newIngFakeVM(t *testing.T, series []ingFakeSeries) *ingFakeVM {
	t.Helper()
	f := &ingFakeVM{status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		f.mu.Lock()
		f.queries = append(f.queries, q)
		status := f.status
		f.mu.Unlock()
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		var match *regexp.Regexp
		if m := ingResourceMatcher.FindStringSubmatch(q); m != nil {
			re, err := regexp.Compile(`^(?:` + strings.ReplaceAll(m[1], `\\`, `\`) + `)$`)
			if err != nil {
				http.Error(w, "cannot parse selector: "+err.Error(), http.StatusUnprocessableEntity)
				return
			}
			match = re
		}
		count := map[string]int{}
		for _, s := range series {
			if match == nil || match.MatchString(s.resourceID) {
				count[s.provider]++
			}
		}
		now := time.Now().Unix()
		var rows []string
		for p, n := range count {
			v := strconv.Itoa(n)
			if strings.HasPrefix(q, "max by") {
				v = strconv.FormatInt(now, 10)
			}
			rows = append(rows, fmt.Sprintf(`{"metric":{"provider":%q},"value":[%d,%q]}`, p, now, v))
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[%s]}}`, strings.Join(rows, ","))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("VICTORIA_URL", srv.URL) // tracker 384: cloud reads use the shared metrics upstream
	return f
}

// take returns the queries seen since the last call.
func (f *ingFakeVM) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.queries
	f.queries = nil
	return out
}

func (f *ingFakeVM) setStatus(code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = code
}

type ingResponse struct {
	Sources   []cloudSourceStatus            `json:"sources"`
	Providers map[string][]cloudSourceStatus `json:"providers"`
}

func ingMetricsRow(t *testing.T, rows []cloudSourceStatus) cloudSourceStatus {
	t.Helper()
	for _, row := range rows {
		if row.SourceType == "metrics" {
			return row
		}
	}
	t.Fatalf("no metrics row in %+v", rows)
	return cloudSourceStatus{}
}

func ingSeed(t *testing.T, s *server, tenant string, rows ...cloud.CloudResource) {
	t.Helper()
	for i := range rows {
		rows[i].AccountID = "123456789012"
		rows[i].Region = "us-west-2"
		rows[i].ResourceName = "res-" + strconv.Itoa(i)
	}
	if err := s.cloud.ReplaceInventory(context.Background(), tenant, rows, nil); err != nil {
		t.Fatalf("seed %s: %v", tenant, err)
	}
}

type ingFixture struct {
	srv                      *httptest.Server
	s                        *server
	admin, alice, bob, carol string
	acmeID, globexID         string
	vm                       *ingFakeVM
}

// newIngFixture: acme owns one aws VM; globex owns an aws VM with five series and
// an azure VM (the provider acme must never learn of); initech owns nothing.
func newIngFixture(t *testing.T) *ingFixture {
	t.Helper()
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	onboard := func(org, tenant, slug string) onboardResponse {
		st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
			"org_name": org, "tenant_name": tenant, "tenant_slug": slug,
		})
		if st != 201 {
			t.Fatalf("onboard %s: %d %s", org, st, b)
		}
		var r onboardResponse
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	acme := onboard("Acme Corp", "Acme Prod", "acme-prod")
	globex := onboard("Globex Inc", "Globex Prod", "globex-prod")
	initech := onboard("Initech", "Initech Prod", "initech-prod")
	user := func(name, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	f := &ingFixture{
		srv: srv, s: s, admin: admin,
		alice:  user("alice-ing", acme.Tenant.ID),
		bob:    user("bob-ing", globex.Tenant.ID),
		carol:  user("carol-ing", initech.Tenant.ID),
		acmeID: acme.Tenant.ID, globexID: globex.Tenant.ID,
	}
	ingSeed(t, s, acme.Tenant.ID, cloud.CloudResource{ResourceID: ingAcmeVM, Provider: "aws"})
	ingSeed(t, s, globex.Tenant.ID,
		cloud.CloudResource{ResourceID: ingGlobexVM, Provider: "aws"},
		cloud.CloudResource{ResourceID: ingGlobexARM, Provider: "azure"})
	f.vm = newIngFakeVM(t, []ingFakeSeries{
		{"aws", ingAcmeVM},
		{"aws", ingGlobexVM}, {"aws", ingGlobexVM}, {"aws", ingGlobexVM}, {"aws", ingGlobexVM}, {"aws", ingGlobexVM},
		{"azure", ingGlobexARM}, {"azure", ingGlobexARM},
		// A cloud_* series with no resource_id: never a scoped caller's.
		{"gcp", ""},
	})
	return f
}

func (f *ingFixture) get(t *testing.T, token, path string) (ingResponse, string) {
	t.Helper()
	st, b := do(t, f.srv, "GET", path, token, nil)
	if st != 200 {
		t.Fatalf("GET %s: %d %s", path, st, b)
	}
	var out ingResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out, string(b)
}

// assertIngSelector requires the two proof queries, each carrying exactly want.
func assertIngSelector(t *testing.T, queries []string, want string) {
	t.Helper()
	if len(queries) != 2 {
		t.Fatalf("want the 2 proof queries, got %d: %q", len(queries), queries)
	}
	for _, q := range queries {
		if !strings.Contains(q, want) {
			t.Fatalf("query must carry selector %s:\n  %s", want, q)
		}
	}
}

func TestCloudIngestionMetricReadIsTenantScoped(t *testing.T) {
	f := newIngFixture(t)
	acmeSel := `{__name__=~"cloud_.+",resource_id=~"i-acme1"}`
	globexSel := `{__name__=~"cloud_.+",resource_id=~"` + regexAlternation([]string{ingGlobexARM, ingGlobexVM}) + `"}`

	assertAcmeOnly := func(t *testing.T, path string) {
		t.Helper()
		got, body := f.get(t, f.alice, path)
		queries := f.vm.take()
		assertIngSelector(t, queries, acmeSel)
		for _, q := range queries {
			if strings.Contains(q, "globex") {
				t.Fatalf("a scoped query named a foreign resource: %s", q)
			}
		}
		for _, foreign := range []string{"azure", "gcp"} {
			if _, ok := got.Providers[foreign]; ok {
				t.Fatalf("provider %s is not acme's and reached the matrix: %s", foreign, body)
			}
		}
		if strings.Contains(body, "globex") || strings.Contains(body, "azure") {
			t.Fatalf("response names the other tenant: %s", body)
		}
		for name, row := range map[string]cloudSourceStatus{
			"provider row": ingMetricsRow(t, got.Providers["aws"]),
			"global row":   ingMetricsRow(t, got.Sources),
		} {
			if row.Volume != 1 || row.Status != "flowing" {
				t.Fatalf("%s must count acme's 1 series only: %+v", name, row)
			}
		}
	}

	t.Run("own series only", func(t *testing.T) { assertAcmeOnly(t, "/api/cloud/ingestion") })
	t.Run("as_tenant into another org is ignored", func(t *testing.T) {
		assertAcmeOnly(t, "/api/cloud/ingestion?as_tenant="+f.globexID)
	})

	t.Run("other tenant symmetrically, with an escaped ARM id", func(t *testing.T) {
		got, body := f.get(t, f.bob, "/api/cloud/ingestion")
		assertIngSelector(t, f.vm.take(), globexSel)
		if strings.Contains(body, ingAcmeVM) {
			t.Fatalf("response names acme: %s", body)
		}
		if v := ingMetricsRow(t, got.Providers["aws"]).Volume; v != 5 {
			t.Fatalf("globex aws must count its own 5 series, got %d", v)
		}
		if v := ingMetricsRow(t, got.Providers["azure"]).Volume; v != 2 {
			t.Fatalf("globex azure must count its own 2 series (the dotted ARM id matched), got %d", v)
		}
	})

	t.Run("cross-tenant caller keeps the fleet-wide read", func(t *testing.T) {
		got, _ := f.get(t, f.admin, "/api/cloud/ingestion")
		queries := f.vm.take()
		wantLast := `max by (provider) (timestamp(last_over_time({__name__=~"cloud_.+"}[24h])))`
		wantCount := `count by (provider) (last_over_time({__name__=~"cloud_.+"}[24h]))`
		if len(queries) != 2 || queries[0] != wantLast || queries[1] != wantCount {
			t.Fatalf("the cross-tenant queries changed: %q", queries)
		}
		if v := ingMetricsRow(t, got.Sources).Volume; v != 9 {
			t.Fatalf("cross-tenant global row must count every series, got %d", v)
		}
		for _, p := range []string{"aws", "azure", "gcp"} {
			if _, ok := got.Providers[p]; !ok {
				t.Fatalf("cross-tenant matrix lost provider %s: %+v", p, got.Providers)
			}
		}
	})

	t.Run("no inventory asks the store nothing and reads off", func(t *testing.T) {
		got, body := f.get(t, f.carol, "/api/cloud/ingestion")
		if q := f.vm.take(); len(q) != 0 {
			t.Fatalf("an empty inventory must not query the store: %q", q)
		}
		if len(got.Providers) != 0 {
			t.Fatalf("no provider may appear: %s", body)
		}
		if row := ingMetricsRow(t, got.Sources); row.Status != "off" || row.Volume != 0 {
			t.Fatalf("no resources is a measured off: %+v", row)
		}
	})

	t.Run("a store that does not answer is unknown, not off", func(t *testing.T) {
		f.vm.setStatus(http.StatusServiceUnavailable)
		defer f.vm.setStatus(http.StatusOK)
		got, _ := f.get(t, f.alice, "/api/cloud/ingestion")
		f.vm.take()
		for name, row := range map[string]cloudSourceStatus{
			"provider row": ingMetricsRow(t, got.Providers["aws"]),
			"global row":   ingMetricsRow(t, got.Sources),
		} {
			if row.Status != cloudStatusUnknown || row.Detail != cloudMetricsUnknownDetail || row.Volume != 0 {
				t.Fatalf("%s must say metrics are unknown: %+v", name, row)
			}
		}
	})
}

// A platform owner's Global view drops a restricted tenant, and the fleet-wide
// read cannot, so that view falls back to the surviving inventory. Scoped INTO
// the restricted tenant it reads nothing, and says "off" rather than a refusal.
func TestCloudIngestionMetricReadObeysOperatorRestriction(t *testing.T) {
	f := newIngFixture(t)
	if _, err := f.s.tenants.SetOperatorRestricted("acme-prod", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	got, body := f.get(t, f.admin, "/api/cloud/ingestion")
	assertIngSelector(t, f.vm.take(),
		`resource_id=~"`+regexAlternation([]string{ingGlobexARM, ingGlobexVM})+`"}`)
	if strings.Contains(body, ingAcmeVM) {
		t.Fatalf("the Global view names a restricted tenant's resource: %s", body)
	}
	if v := ingMetricsRow(t, got.Providers["aws"]).Volume; v != 5 {
		t.Fatalf("aws must exclude the restricted tenant's series, got %d", v)
	}

	got, _ = f.get(t, f.admin, "/api/cloud/ingestion?as_tenant="+f.acmeID)
	if q := f.vm.take(); len(q) != 0 {
		t.Fatalf("a denied view must not query the store: %q", q)
	}
	if row := ingMetricsRow(t, got.Sources); row.Status != "off" || row.Volume != 0 {
		t.Fatalf("a denied view must read as nothing: %+v", row)
	}
}

func TestCloudResourceIDBatches(t *testing.T) {
	t.Run("an empty or invalid id never reaches the alternation", func(t *testing.T) {
		got, ok := cloudResourceIDBatches([]cloud.CloudResource{
			{ResourceID: ""}, {ResourceID: `bad"quote`}, {ResourceID: `bad\slash`},
			{ResourceID: strings.Repeat("x", cloud.SeriesMaxResourceIDLen+1)},
			{ResourceID: "i-b"}, {ResourceID: "i-a"}, {ResourceID: "i-a"},
		})
		if !ok || len(got) != 1 || got[0] != "i-a|i-b" {
			t.Fatalf("want one sorted, deduped batch, got %q ok=%v", got, ok)
		}
	})
	t.Run("nothing valid renders no batch", func(t *testing.T) {
		got, ok := cloudResourceIDBatches([]cloud.CloudResource{{ResourceID: ""}})
		if !ok || len(got) != 0 {
			t.Fatalf("an empty alternation would match unlabelled series: %q ok=%v", got, ok)
		}
	})
	t.Run("metacharacters stay literal", func(t *testing.T) {
		got, _ := cloudResourceIDBatches([]cloud.CloudResource{{ResourceID: "a.*|b"}})
		if len(got) != 1 || got[0] != `a\\.\\*\\|b` {
			t.Fatalf("id must render as a literal: %q", got)
		}
	})
	t.Run("batches fit the store's query limit and lose nothing", func(t *testing.T) {
		var res []cloud.CloudResource
		for i := 0; i < 2500; i++ {
			res = append(res, cloud.CloudResource{ResourceID: fmt.Sprintf("i-%017d", i)})
		}
		got, ok := cloudResourceIDBatches(res)
		if !ok || len(got) < 2 {
			t.Fatalf("want several batches within the cap, got %d ok=%v", len(got), ok)
		}
		total := 0
		for _, b := range got {
			if q := cloudMetricLastQuery(b); len(q) > 16384 {
				t.Fatalf("query of %d bytes exceeds -search.maxQueryLen", len(q))
			}
			total += strings.Count(b, "|") + 1
		}
		if total != len(res) {
			t.Fatalf("batches lost ids: %d of %d", total, len(res))
		}
	})
}

// The paths with no HTTP trigger: an inventory that cannot be turned into a
// selector must report unknown, and must not fall back to any store read.
func TestReadCloudMetricProofFailsClosed(t *testing.T) {
	vm := newIngFakeVM(t, []ingFakeSeries{{"aws", "i-a"}})
	ctx := context.Background()
	var oversized []cloud.CloudResource
	for i := 0; i < 6000; i++ {
		oversized = append(oversized, cloud.CloudResource{ResourceID: fmt.Sprintf("i-%040d", i)})
	}
	cases := []struct {
		name   string
		res    []cloud.CloudResource
		invErr error
	}{
		{"inventory unreadable", []cloud.CloudResource{{ResourceID: "i-a"}}, errors.New("store down")},
		{"inventory past the budget", oversized, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := readCloudMetricProof(ctx, tc.res, tc.invErr, false)
			if p.known || len(p.last) != 0 || len(p.series) != 0 {
				t.Fatalf("must be unknown and empty: %+v", p)
			}
			if q := vm.take(); len(q) != 0 {
				t.Fatalf("must not query the store: %q", q)
			}
		})
	}
	t.Run("a partial answer is not an answer", func(t *testing.T) {
		vm.setStatus(http.StatusInternalServerError)
		defer vm.setStatus(http.StatusOK)
		if p := readCloudMetricProof(ctx, []cloud.CloudResource{{ResourceID: "i-a"}}, nil, false); p.known || p.last != nil {
			t.Fatalf("must be unknown: %+v", p)
		}
		vm.take()
	})
}
