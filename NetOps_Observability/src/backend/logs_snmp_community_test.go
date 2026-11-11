// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// logs_snmp_community_test.go — documents stored before 2026-11-09 hold the
// v1/v2c community in `_source`. Retention ages them out, but until then no read
// path may serve the value, and the strip must not change what a caller's tenant
// scope selects (CLAUDE.md §3a).
//
// The fake OpenSearch below deliberately IGNORES `_source.excludes`, so these
// tests fail if the response-side strip is removed even though the real store
// would have honoured the exclude.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/logexport"
	"netops/backend/internal/ratelimit"
)

const fabricatedStoredCommunity = "fabricated-community-7f3a"

// storedTrapReply is one pre-fix trap document and one document with no message,
// which makes the tabular export fall back to the raw document.
const storedTrapReply = `{"took":1,"hits":{"total":{"value":2,"relation":"eq"},"hits":[` +
	`{"_index":"netops-snmptrap-acme-2026.11.09","_id":"a","sort":[1,"a"],"_source":{"timestamp":"2026-11-09T02:25:00Z",` +
	`"hostname":"acme-core","severity":"warning","message":"linkDown","tenant_id":"acme","snmp_version":"v2c","snmp_community":"` + fabricatedStoredCommunity + `"}},` +
	`{"_index":"netops-snmptrap-acme-2026.11.09","_id":"b","sort":[2,"b"],"_source":{"timestamp":"2026-11-09T02:26:00Z",` +
	`"hostname":"acme-core","tenant_id":"acme","snmp_version":"v1","snmp_community":"` + fabricatedStoredCommunity + `"}}]}}`

func assertNoCommunity(t *testing.T, where, body string) {
	t.Helper()
	if strings.Contains(body, fabricatedStoredCommunity) || strings.Contains(body, `"snmp_community"`) {
		t.Fatalf("%s served the stored community:\n%s", where, body)
	}
}

func TestLogSearchNeverServesTheStoredCommunity(t *testing.T) {
	for _, signal := range []string{"snmptrap", "", "syslog", "flows"} {
		t.Run("signal="+signal, func(t *testing.T) {
			_, bodies := fakeOS(t, storedTrapReply)
			s := logsTestServer(t)
			w := httptest.NewRecorder()
			s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal="+signal, "", acme()))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			assertNoCommunity(t, "log search", w.Body.String())
			if !strings.Contains(w.Body.String(), `"message":"linkDown"`) {
				t.Fatalf("the document itself must still be served: %s", w.Body.String())
			}
			if !strings.Contains((*bodies)[0], `"_source":{"excludes":["snmp_community"]}`) {
				t.Errorf("the store must be asked not to send the field: %s", (*bodies)[0])
			}
		})
	}
}

// Default-closed: a success body the strip cannot check is refused, not relayed.
func TestLogSearchRefusesAResponseItCannotCheck(t *testing.T) {
	fakeOS(t, `{"hits":{"hits":[{"_source":{"snmp_community":"`+fabricatedStoredCommunity)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=snmptrap", "", acme()))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", w.Code)
	}
	assertNoCommunity(t, "refused log search", w.Body.String())
}

// §3a: the read filter removes a field; it must not change the index pattern or
// the per-document tenant clause of the request.
func TestLogSearchStripDoesNotWidenTenantScope(t *testing.T) {
	paths, bodies := fakeOS(t, storedTrapReply)
	s := logsTestServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?signal=snmptrap&as_tenant=globex", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	p := (*paths)[0]
	if !strings.Contains(p, "netops-snmptrap-acme-*") || !strings.Contains(p, "netops-snmptrap-untagged-*") {
		t.Errorf("index pattern not tenant-scoped: %q", p)
	}
	if strings.Contains(p, "globex") || strings.Contains(p, "netops-snmptrap-*") {
		t.Errorf("TENANT LEAK: scope widened: %q", p)
	}
	body := (*bodies)[0]
	if !strings.Contains(body, `"tenant_id":"acme"`) {
		t.Errorf("per-document tenant clause lost: %s", body)
	}
	if strings.Contains(body, "globex") {
		t.Errorf("TENANT LEAK: as_tenant reached the query: %s", body)
	}
}

func TestExportNeverServesTheStoredCommunity(t *testing.T) {
	for _, format := range []string{"json", "ndjson", "csv", "xlsx"} {
		t.Run(format, func(t *testing.T) {
			_, bodies := fakeOS(t, storedTrapReply)
			s := logsTestServer(t)
			s.exportLimiter = ratelimit.New()
			w := httptest.NewRecorder()
			s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=snmptrap&mode=sync&format="+format, "", acme()))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if format != "xlsx" { // a zip: asserted through the fetch below
				assertNoCommunity(t, format+" export", w.Body.String())
			}
			last := (*bodies)[len(*bodies)-1]
			if !strings.Contains(last, `"excludes":["snmp_community"]`) {
				t.Errorf("the store must be asked not to send the field: %s", last)
			}
		})
	}
}

// FetchBounded is the one fetch behind the sync export and the large queued
// export (processExport), so this is the queued path too: every format renders
// from what it returns.
func TestExportFetchStripsBeforeEveryProjection(t *testing.T) {
	calls := 0
	search := func(_, _ string, _ any) (*http.Response, error) {
		calls++
		reply := `{"hits":{"hits":[]}}`
		if calls == 1 {
			reply = storedTrapReply
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(reply))}, nil
	}
	start, end := time.Now().Add(-time.Hour), time.Now()
	data, err := logexport.FetchBounded(context.Background(), search, logexport.Spec{Signal: "snmptrap", Tenant: "acme"}, start, end, 100, 1<<20, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Rows) != 2 || len(data.Raw) != 2 {
		t.Fatalf("rows=%d raw=%d, want 2 each", len(data.Rows), len(data.Raw))
	}
	for _, raw := range data.Raw {
		assertNoCommunity(t, "raw export document", string(raw))
	}
	for _, row := range data.Rows { // row b has no message: its cell is the raw document
		assertNoCommunity(t, "tabular export row", strings.Join(row, " "))
	}
	if !strings.Contains(data.Rows[1][3], "snmp_version") {
		t.Fatalf("the raw-document fallback must still work: %v", data.Rows[1])
	}
	for _, format := range []string{"json", "ndjson", "csv", "xlsx"} {
		art, err := logexport.Encode(context.Background(), format, logexport.Columns, data)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		assertNoCommunity(t, format+" artifact", string(art.Bytes))
	}
}

func TestExportFetchFailsOnADocumentItCannotCheck(t *testing.T) {
	// A hit whose _source is a JSON scalar naming the field: decodes as a hit but
	// is not a document the strip can vouch for.
	reply := `{"hits":{"hits":[{"_index":"i","_id":"a","sort":[1],"_source":"snmp_community"}]}}`
	search := func(_, _ string, _ any) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(reply))}, nil
	}
	start, end := time.Now().Add(-time.Hour), time.Now()
	data, err := logexport.FetchBounded(context.Background(), search, logexport.Spec{Signal: "snmptrap", Tenant: "acme"}, start, end, 100, 1<<20, nil)
	if err == nil {
		t.Fatalf("an uncheckable document must fail the export, got %+v", data)
	}
}

// §3a for the export door: the frozen spec still names only the caller's scope.
func TestExportStripDoesNotWidenTenantScope(t *testing.T) {
	paths, bodies := fakeOS(t, storedTrapReply)
	s := logsTestServer(t)
	s.exportLimiter = ratelimit.New()
	w := httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?signal=snmptrap&mode=sync&format=json&as_tenant=globex", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	for i, p := range *paths {
		if strings.Contains(p, "globex") || strings.Contains(p, "netops-snmptrap-*") {
			t.Errorf("TENANT LEAK: path %q", p)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte((*bodies)[i]), &body); err != nil {
			t.Fatal(err)
		}
		if strings.Contains((*bodies)[i], "globex") || !strings.Contains((*bodies)[i], `"tenant_id":"acme"`) {
			t.Errorf("tenant clause wrong: %s", (*bodies)[i])
		}
	}
}
