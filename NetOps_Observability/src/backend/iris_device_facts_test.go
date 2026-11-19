// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_device_facts_test.go — the DISCOVERED-device facts seam behind skill
// applicability (ai/skill_facts.go, NetClaw ingestion Batch 0): what it derives,
// that every fact a compiled skill tests can actually be derived, and §3a rule 5
// (org_isolation_test.go is the template; the adversarial fixture is the same
// two-tenant overlay the whole-network topology test uses).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/collectors"
	"netops/backend/internal/devmon"
	"netops/backend/models"
	"netops/backend/topology"
)

func deviceFactsOf(t *testing.T, s *server, claims jwtClaims, id string) (ai.DeviceFacts, error) {
	t.Helper()
	deps := aiTSDeps(t, s, claims)
	if deps.DeviceFacts == nil {
		t.Fatal("the device-facts seam must be wired when there is an inventory")
	}
	return deps.DeviceFacts(context.Background(), aiTSPrincipal(), id)
}

func factHolds(f ai.DeviceFacts, key, value string) bool {
	for _, v := range f.Seen(key) {
		if v == value {
			return true
		}
	}
	got, ok := f.Value(key)
	return ok && got == value
}

// §3a: the caller's own device answers with its own facts; another tenant's
// device is ErrNotFound — indistinguishable from a device that does not exist.
func TestIrisDeviceFactsAreTheCallersOwn(t *testing.T) {
	s := netTopoServer(t)
	f, err := deviceFactsOf(t, s, acme(), "acme-e0")
	if err != nil {
		t.Fatalf("own device: %v", err)
	}
	if !factHolds(f, ai.FactAdjacency, "overlay") || !factHolds(f, ai.FactAdjacency, "bfd") {
		t.Fatalf("acme-e0 is an overlay member with BFD sessions: overlay=%v", f.Seen(ai.FactAdjacency))
	}
	if !factHolds(f, ai.FactAdjacency, "lldp") {
		t.Fatalf("acme-e0 has its own LLDP neighbour: %v", f.Seen(ai.FactAdjacency))
	}
	if !factHolds(f, ai.FactTelemetry, "snmp") {
		t.Fatalf("an addressed device with no preferred protocol is collected by SNMP: %v", f.Seen(ai.FactTelemetry))
	}

	for _, foreign := range []string{"globex-e0", "GLOBEX-E1", "no-such-device"} {
		if _, err := deviceFactsOf(t, s, acme(), foreign); !errors.Is(err, ai.ErrNotFound) {
			t.Fatalf("TENANT LEAK: acme read facts of %q (err=%v)", foreign, err)
		}
	}
	// as_tenant never widens a non-owner.
	sneaky := acme()
	sneaky.ActingTenant = "globex"
	if _, err := deviceFactsOf(t, s, sneaky, "globex-e0"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("TENANT LEAK: as_tenant reached globex-e0 (err=%v)", err)
	}
	// The cross-tenant LLDP row (globex-e1 naming acme-e0) is globex's own
	// telemetry: it must not make acme-e0's facts depend on globex. A globex
	// caller must not see acme-e0 at all.
	if _, err := deviceFactsOf(t, s, globex(), "acme-e0"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("TENANT LEAK: globex read acme-e0's facts (err=%v)", err)
	}
}

// The pure fold: observations only; an absence only where the source that
// would show it was read.
func TestDeriveDeviceFacts(t *testing.T) {
	dev := models.Device{ID: "r1", Name: "core-1", Address: "10.0.0.1", Vendor: "Juniper", OS: "JUNOS", Model: "MX204"}
	in := deviceFactInputs{
		dev:  dev,
		role: topology.RoleResult{Role: topology.DevRoleCoreRouter, Confidence: topology.RoleConfStrong},
		links: []topoLink{
			{Source: "r1", Target: "r2", SourceProto: "lldp+cdp"},
			{Source: "r2", Target: "r1", SourceProto: "bgp_ls", IGP: "isis-l2"},
			{Source: "x", Target: "y", SourceProto: "bgp_ls", IGP: "ospfv2"}, // not this device
		},
		linksRead:   true,
		externalBGP: 2,
		overlayRead: true, // read, and r1 published no overlay facts
	}
	f := deriveDeviceFacts(in)
	if v, _ := f.Value(ai.FactRole); v != topology.DevRoleCoreRouter {
		t.Fatalf("role = %q", v)
	}
	if v, ok := f.Value(ai.FactDialect); !ok || v == ai.DialectNone {
		t.Fatalf("a Junos platform resolves to its dialect, got %q", v)
	}
	seen := strings.Join(f.Seen(ai.FactAdjacency), ",")
	if seen != "bgp,isis,lldp" {
		t.Fatalf("adjacency seen = %s, want bgp,isis,lldp (never another device's OSPF)", seen)
	}
	// The overlay snapshot was read and r1 is not in it → it is not an overlay
	// member; OSPF was never readable for r1 → it stays unseen (unknown).
	if factHolds(f, ai.FactAdjacency, "overlay") || factHolds(f, ai.FactAdjacency, "ospf") {
		t.Fatalf("r1 is not an overlay member and its OSPF is unknown: %v", f.Seen(ai.FactAdjacency))
	}

	// A weak role never rules a method out.
	weak := deriveDeviceFacts(deviceFactInputs{dev: dev, role: topology.RoleResult{Role: topology.DevRoleFirewall, Confidence: topology.RoleConfWeak}})
	if _, ok := weak.Value(ai.FactRole); ok {
		t.Fatal("a weak role classification must stay unknown")
	}
	// Unread links: no adjacency fact at all, and no absence invented.
	unread := deriveDeviceFacts(deviceFactInputs{dev: dev, links: in.links, linksRead: false})
	if len(unread.Seen(ai.FactAdjacency)) != 0 {
		t.Fatalf("unread links must not produce adjacency facts: %v", unread.Seen(ai.FactAdjacency))
	}
	// An empty platform is unknown; an unsupported one is "none".
	if _, ok := deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "z"}}).Value(ai.FactDialect); ok {
		t.Fatal("an empty platform must leave the dialect unknown")
	}
	if v, _ := deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "z", Vendor: "acme", OS: "toaster"}}).Value(ai.FactDialect); v != ai.DialectNone {
		t.Fatalf("an unsupported platform reads as none, got %q", v)
	}
	// A controller-sourced device is collected through the controller only.
	ctl := deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "c", Address: "10.0.0.9", Source: devmon.SourceController}})
	if !factHolds(ctl, ai.FactTelemetry, "api") || factHolds(ctl, ai.FactTelemetry, "snmp") {
		t.Fatalf("controller device telemetry = %v", ctl.Seen(ai.FactTelemetry))
	}
	// Neighbour rows the device reports (tracker 415): seen, any VRF — an
	// iBGP- or VRF-only router with no external peer is still a BGP speaker.
	// A protocol with no rows stays unknown, never absent.
	nb := deriveDeviceFacts(deviceFactInputs{dev: dev, protoNeighbors: map[string]bool{"ospf": true, "bgp": true}})
	if got := strings.Join(nb.Seen(ai.FactAdjacency), ","); got != "bgp,ospf" {
		t.Fatalf("neighbour rows: adjacency seen = %s, want bgp,ospf", got)
	}
	if factHolds(nb, ai.FactAdjacency, "isis") {
		t.Fatal("no IS-IS rows must leave IS-IS unknown")
	}
	// Overlay member with sessions → overlay and bfd observed.
	member := deriveDeviceFacts(deviceFactInputs{dev: dev, overlayRead: true, overlay: &collectors.OverlayDeviceFacts{
		DeviceID: "r1", Peers: []collectors.OverlayPeer{{SystemIP: "1.1.1.1", ColorPairs: []collectors.OverlayColorPairs{{LocalColor: "mpls", Sessions: 2, Up: 2}}}},
	}})
	if !factHolds(member, ai.FactAdjacency, "overlay") || !factHolds(member, ai.FactAdjacency, "bfd") {
		t.Fatalf("overlay member: %v", member.Seen(ai.FactAdjacency))
	}
}

// Every fact value a compiled skill's applies_when tests must be one the
// server seam can actually ESTABLISH — otherwise the line could only ever be
// unknown, a rule that silently never decides anything. Role and dialect are
// derived by the classifier and the dialect registry for every value in their
// vocabulary; adjacency and telemetry values are proven by driving the fold.
func TestEverySkillAppliesWhenIsDerivable(t *testing.T) {
	derivable := map[string]bool{}
	note := func(f ai.DeviceFacts) {
		for _, k := range []string{ai.FactAdjacency, ai.FactTelemetry} {
			for _, v := range f.Seen(k) {
				derivable[k+"="+v] = true
			}
		}
	}
	dev := models.Device{ID: "d", Address: "10.0.0.1"}
	note(deriveDeviceFacts(deviceFactInputs{dev: dev, linksRead: true, externalBGP: 1, links: []topoLink{
		{Source: "d", Target: "e", SourceProto: "lldp"},
		{Source: "d", Target: "e", SourceProto: "bgp_ls", IGP: "isis-l1"},
		{Source: "d", Target: "f", SourceProto: "bgp_ls", IGP: "ospfv2"},
	}}))
	note(deriveDeviceFacts(deviceFactInputs{dev: dev, overlayRead: true, overlay: &collectors.OverlayDeviceFacts{
		Peers: []collectors.OverlayPeer{{ColorPairs: []collectors.OverlayColorPairs{{Sessions: 1}}}},
	}}))
	note(deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "g", Address: "10.0.0.2", Labels: map[string]string{"gnmi": "true"}}}))
	note(deriveDeviceFacts(deviceFactInputs{dev: models.Device{ID: "c", Address: "10.0.0.3", Source: devmon.SourceController}}))

	set, err := ai.LoadSkills()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, n := range set.Names() {
		sk, _ := set.Get(n)
		for _, c := range sk.AppliesWhen {
			key := strings.TrimPrefix(c.Key, ai.CondFactPrefix)
			if key == ai.FactRole || key == ai.FactDialect || key == ai.FactWANFlavor {
				continue // set straight from the classifier / dialect registry
			}
			for _, v := range strings.Split(c.Value, "|") {
				checked++
				if !derivable[key+"="+v] {
					t.Errorf("%s: applies_when %s — %s=%s can never be established by deriveDeviceFacts", n, c, key, v)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no compiled applies_when value was checked — the corpus no longer exercises the seam")
	}
}

// §3a for the neighbour-row read (tracker 415): a HOSTILE fake VictoriaMetrics
// answers every query with BOTH tenants' series whatever filters it was sent.
// acme-e0's facts must come only from acme-e0's own rows, every read must carry
// the caller's boundary, and the device selector must never name another
// tenant's device.
func TestIrisDeviceFactsNeighbourRowsAreTheCallersOwn(t *testing.T) {
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
		case strings.Contains(q, "device_ospf_nbr_state"):
			rows = []string{`{"metric":{"device":"acme-e0"},"value":[1,"2"]}`, `{"metric":{"device":"globex-e0"},"value":[1,"3"]}`}
		case strings.Contains(q, "device_isis_adj_state"), strings.Contains(q, "device_bgp_peer_state"):
			rows = []string{`{"metric":{"device":"globex-e0"},"value":[1,"4"]}`}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(rows, ",") + `]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	t.Setenv("METRICS_URL", vm.URL)

	s := netTopoServer(t)
	f, err := deviceFactsOf(t, s, acme(), "acme-e0")
	if err != nil {
		t.Fatalf("own device: %v", err)
	}
	if !factHolds(f, ai.FactAdjacency, "ospf") {
		t.Fatalf("acme-e0 reports OSPF neighbour rows: %v", f.Seen(ai.FactAdjacency))
	}
	if factHolds(f, ai.FactAdjacency, "isis") || factHolds(f, ai.FactAdjacency, "bgp") {
		t.Fatalf("TENANT LEAK: globex-e0's IS-IS/BGP rows changed acme-e0's facts: %v", f.Seen(ai.FactAdjacency))
	}
	mu.Lock()
	defer mu.Unlock()
	var nbQueries int
	for _, q := range queries {
		if !strings.Contains(q, "_nbr_state") && !strings.Contains(q, "_adj_state") && !strings.Contains(q, "_peer_state{device") {
			continue
		}
		nbQueries++
		if strings.Contains(q, "globex") {
			t.Errorf("the neighbour read names another tenant's device: %s", q)
		}
	}
	if nbQueries < 3 {
		t.Fatalf("expected the three neighbour reads, saw %d in %v", nbQueries, queries)
	}
	if len(filters) == 0 {
		t.Fatal("the neighbour reads carried NO extra_filters[] — an unscoped read")
	}
	for _, fl := range filters {
		if strings.Contains(fl, "globex") {
			t.Errorf("acme's boundary names globex: %s", fl)
		}
	}
}
