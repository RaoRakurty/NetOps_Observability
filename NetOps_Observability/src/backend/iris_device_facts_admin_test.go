// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_device_facts_admin_test.go — tracker 415 PR 3/4: the admin-state
// scalars (ospfAdminStat, ospfv3AdminStatus, isisSysAdminState, bgpLocalAs)
// and the ONLY rule that may establish an IGP absent. Owner 2026-11-19: never
// conclude "no OSPF" from OSPFv2 alone.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/models"
)

func absentOf(f ai.DeviceFacts, value string) bool {
	return slices.Contains(f.Absent(ai.FactAdjacency), value)
}

// The truth table. Absent needs: the admin scalar fresh and off, the neighbour
// read answered with no rows — and for OSPF both v2 AND v3 off. Anything less
// is unknown; enabled is seen.
func TestDeriveDeviceFactsAdminState(t *testing.T) {
	dev := models.Device{ID: "r1", Name: "core-1"}
	read := map[string]bool{"ospf": true, "isis": true, "bgp": true}
	type want struct{ seen, absent []string }
	cases := []struct {
		name string
		in   deviceFactInputs
		want want
	}{
		{"isis off, no rows → absent",
			deviceFactInputs{protoAdmin: map[string]int{"isis": 2}, protoNeighborsRead: read},
			want{absent: []string{"isis"}}},
		{"isis off but a neighbour row → seen (an observation wins)",
			deviceFactInputs{protoAdmin: map[string]int{"isis": 2}, protoNeighborsRead: read, protoNeighbors: map[string]bool{"isis": true}},
			want{seen: []string{"isis"}}},
		{"isis off, neighbour read failed → unknown",
			deviceFactInputs{protoAdmin: map[string]int{"isis": 2}},
			want{}},
		{"isis on → seen",
			deviceFactInputs{protoAdmin: map[string]int{"isis": 1}, protoNeighborsRead: read},
			want{seen: []string{"isis"}}},
		{"ospfv2 off alone → unknown (a v3-only router reports v2 disabled)",
			deviceFactInputs{protoAdmin: map[string]int{"ospf": 2}, protoNeighborsRead: read},
			want{}},
		{"ospfv2 off, v3 marker missing → unknown",
			deviceFactInputs{protoAdmin: map[string]int{"ospf": 2, "isis": 0}, protoNeighborsRead: read},
			want{}},
		{"ospf v2 and v3 off, no rows → absent",
			deviceFactInputs{protoAdmin: map[string]int{"ospf": 2, "ospfv3": 2}, protoNeighborsRead: read},
			want{absent: []string{"ospf"}}},
		{"ospf v2 off, v3 on → seen",
			deviceFactInputs{protoAdmin: map[string]int{"ospf": 2, "ospfv3": 1}, protoNeighborsRead: read},
			want{seen: []string{"ospf"}}},
		{"ospf both off but a BGP-LS link says OSPF → seen",
			deviceFactInputs{protoAdmin: map[string]int{"ospf": 2, "ospfv3": 2}, protoNeighborsRead: read, linksRead: true,
				links: []topoLink{{Source: "r1", Target: "r2", SourceProto: "bgp_ls", IGP: "ospfv2"}}},
			want{seen: []string{"ospf"}}},
		{"non-zero local AS → bgp seen; there is no BGP absent",
			deviceFactInputs{bgpLocalAS: true, protoNeighborsRead: read},
			want{seen: []string{"bgp"}}},
		{"nothing answered → nothing known",
			deviceFactInputs{protoNeighborsRead: read},
			want{}},
	}
	for _, c := range cases {
		c.in.dev = dev
		f := deriveDeviceFacts(c.in)
		seen, absent := f.Seen(ai.FactAdjacency), f.Absent(ai.FactAdjacency)
		if strings.Join(seen, ",") != strings.Join(c.want.seen, ",") || strings.Join(absent, ",") != strings.Join(c.want.absent, ",") {
			t.Errorf("%s: seen=%v absent=%v, want seen=%v absent=%v", c.name, seen, absent, c.want.seen, c.want.absent)
		}
	}
}

// A guard: OSPF and IS-IS absence must be DERIVABLE (a rule that can never
// fire would silently leave every reroute "could not be established"), and
// BGP absence must NOT be (no source proves it).
func TestIGPAbsenceIsDerivableAndBGPAbsenceIsNot(t *testing.T) {
	read := map[string]bool{"ospf": true, "isis": true, "bgp": true}
	f := deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "d"}, protoNeighborsRead: read,
		protoAdmin: map[string]int{"ospf": 2, "ospfv3": 2, "isis": 2}})
	if !absentOf(f, "ospf") || !absentOf(f, "isis") {
		t.Fatalf("ospf/isis absence not derivable: %v", f.Absent(ai.FactAdjacency))
	}
	if absentOf(f, "bgp") {
		t.Fatal("bgp absence has no proving source and must never be derived")
	}
}

// §3a for the admin-state reads: a HOSTILE fake VictoriaMetrics answers with
// BOTH tenants' admin series. globex-e0 says IS-IS is ON; acme-e0 says it is
// OFF with no IS-IS rows. acme-e0 must read absent from its own series only,
// and every read must carry acme's boundary and name only acme-e0.
func TestIrisDeviceFactsAdminStateIsTheCallersOwn(t *testing.T) {
	var mu sync.Mutex
	var queries, filters []string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		mu.Lock()
		queries = append(queries, q)
		filters = append(filters, r.URL.Query()["extra_filters[]"]...)
		mu.Unlock()
		var rows []string
		switch {
		case strings.Contains(q, "device_isis_admin_state"):
			rows = []string{`{"metric":{"device":"acme-e0"},"value":[1,"2"]}`, `{"metric":{"device":"globex-e0"},"value":[1,"1"]}`}
		case strings.Contains(q, "device_ospf_admin_state"):
			rows = []string{`{"metric":{"device":"globex-e0"},"value":[1,"1"]}`}
		case strings.Contains(q, "device_bgp_local_as"):
			rows = []string{`{"metric":{"device":"globex-e0"},"value":[1,"65001"]}`}
		case strings.Contains(q, "device_isis_adj_state"):
			rows = []string{`{"metric":{"device":"globex-e0"},"value":[1,"3"]}`}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rows, ",") + `]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	t.Setenv("METRICS_URL", vm.URL)

	s := netTopoServer(t)
	deps := aiTSDeps(t, s, acme())
	f, err := deps.DeviceFacts(context.Background(), aiTSPrincipal(), "acme-e0")
	if err != nil {
		t.Fatalf("own device: %v", err)
	}
	if !absentOf(f, "isis") {
		t.Fatalf("acme-e0 reports IS-IS off with no rows — want absent; seen=%v absent=%v",
			f.Seen(ai.FactAdjacency), f.Absent(ai.FactAdjacency))
	}
	for _, p := range []string{"isis", "ospf", "bgp"} {
		if factHolds(f, ai.FactAdjacency, p) {
			t.Errorf("TENANT LEAK: globex-e0's %s series changed acme-e0's facts: %v", p, f.Seen(ai.FactAdjacency))
		}
	}
	if absentOf(f, "ospf") {
		t.Error("no OSPF admin marker for acme-e0: OSPF must stay unknown, not absent")
	}
	mu.Lock()
	defer mu.Unlock()
	var adminQueries int
	for _, q := range queries {
		if !strings.Contains(q, "_admin_state") && !strings.Contains(q, "device_bgp_local_as") {
			continue
		}
		adminQueries++
		if strings.Contains(q, "globex") {
			t.Errorf("an admin-state read names another tenant's device: %s", q)
		}
	}
	if adminQueries != 4 {
		t.Fatalf("expected the four admin-state reads, saw %d in %v", adminQueries, queries)
	}
	if len(filters) == 0 {
		t.Fatal("the admin-state reads carried NO extra_filters[] — an unscoped read")
	}
	for _, fl := range filters {
		if strings.Contains(fl, "globex") {
			t.Errorf("acme's boundary names globex: %s", fl)
		}
	}
}
