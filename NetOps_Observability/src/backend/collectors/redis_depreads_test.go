// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// redis_depreads_test.go — tracker 307, the four remaining single-key
// dependency reads.
//
// FetchIfAddrMap, FetchRoutingDirection, FetchIfIndexMap and FetchWANCircuits
// each folded every outcome into one `if err != nil || raw == "" { return
// <empty>, nil }`. A DEAD channel therefore answered exactly like an ABSENT
// key: "the SNMP collector has published no interface addresses", "the BGP-LS
// SPF has computed no forwarding direction", "the api has published no WAN
// circuits" — three statements about the estate, asserted with a nil error,
// none of which anyone had looked up. It is the same fold tracker 290 closed in
// FetchTopologyLinks in this file and review 3.2-18 closed in FetchDEMRuns.
//
// Each function is held to the three-way answer:
//
//	(a) the connection dies            → an ERROR, classified as transport
//	(b) an absent / empty key          → the empty result, NIL error
//	(c) a published payload            → parsed
//	(d) a payload that will not decode → an ERROR (we authored it: corruption)

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// ---- (a) a dead channel is a failure, never an empty answer ----------------

func TestFetchIfAddrMapReportsADeadChannel(t *testing.T) {
	fakeRedis(t, "") // the GET is read, then the connection is closed unanswered
	m, err := FetchIfAddrMap(context.Background())
	if err == nil {
		t.Fatalf("a dead channel returned a nil error with %d device(s) — every caller is told the interface registry is EMPTY, which is a statement about the estate nobody checked", len(m))
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("got %d device(s) from a read that never happened, want 0", len(m))
	}
}

func TestFetchRoutingDirectionReportsADeadChannel(t *testing.T) {
	fakeRedis(t, "")
	pairs, err := FetchRoutingDirection(context.Background())
	if err == nil {
		t.Fatalf("a dead channel returned a nil error with %d pair(s) — the C7.5 direction source is told the SPF computed nothing", len(pairs))
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
}

func TestFetchIfIndexMapReportsADeadChannel(t *testing.T) {
	fakeRedis(t, "")
	m, err := FetchIfIndexMap(context.Background())
	if err == nil {
		t.Fatalf("a dead channel returned a nil error with %d device(s) — the ifIndex bridge is told no interface has an index", len(m))
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
}

func TestFetchWANCircuitsReportsADeadChannel(t *testing.T) {
	fakeRedis(t, "")
	tg, err := FetchWANCircuits(context.Background())
	if err == nil {
		t.Fatalf("a dead channel returned a nil error with %d target(s) — the echo collector silently falls back to WAN_ECHO_TARGETS as though the api had published nothing", len(tg))
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
}

// ---- (b) an absent or empty key is the ordinary not-published-yet state ----

func TestFetchIfAddrMapTreatsAnAbsentKeyAsNothingPublished(t *testing.T) {
	fakeRedis(t, "$-1\r\n") // nil bulk: the SNMP collector never published
	m, err := FetchIfAddrMap(context.Background())
	if err != nil {
		t.Fatalf("an unpublished key was reported as a failure: %v", err)
	}
	if m == nil {
		t.Error("the absent case must still hand back a usable (non-nil) map")
	}
	if len(m) != 0 {
		t.Errorf("got %d device(s), want 0", len(m))
	}
}

func TestFetchRoutingDirectionTreatsAnAbsentKeyAsNoLSDB(t *testing.T) {
	fakeRedis(t, "$0\r\n\r\n") // empty bulk
	pairs, err := FetchRoutingDirection(context.Background())
	if err != nil {
		t.Fatalf("an unpublished key was reported as a failure: %v", err)
	}
	if pairs == nil {
		t.Error("the absent case must still hand back a usable (non-nil) slice — the enricher marshals it straight to JSON")
	}
	if len(pairs) != 0 {
		t.Errorf("got %d pair(s), want 0", len(pairs))
	}
}

func TestFetchIfIndexMapTreatsAnAbsentKeyAsNothingPublished(t *testing.T) {
	fakeRedis(t, "$-1\r\n")
	m, err := FetchIfIndexMap(context.Background())
	if err != nil {
		t.Fatalf("an unpublished key was reported as a failure: %v", err)
	}
	if m == nil {
		t.Error("the absent case must still hand back a usable (non-nil) map")
	}
}

func TestFetchWANCircuitsTreatsAnAbsentKeyAsNoPublishedList(t *testing.T) {
	fakeRedis(t, "$-1\r\n")
	tg, err := FetchWANCircuits(context.Background())
	if err != nil {
		t.Fatalf("an unpublished key was reported as a failure: %v", err)
	}
	if len(tg) != 0 {
		t.Errorf("got %d target(s), want 0 — the collector then falls back to WAN_ECHO_TARGETS", len(tg))
	}
}

// ---- (c) a published payload is parsed ------------------------------------

func TestFetchIfAddrMapParsesAPublishedMap(t *testing.T) {
	raw := mustJSON(t, map[string]map[string]string{
		"spine-1": {"10.0.0.1": "Ethernet1"},
	})
	fakeRedis(t, respBulk(raw))
	m, err := FetchIfAddrMap(context.Background())
	if err != nil {
		t.Fatalf("FetchIfAddrMap: %v", err)
	}
	if m["spine-1"]["10.0.0.1"] != "Ethernet1" {
		t.Errorf("got %#v, want spine-1/10.0.0.1 → Ethernet1", m)
	}
}

func TestFetchRoutingDirectionParsesPublishedPairs(t *testing.T) {
	raw := mustJSON(t, []RoutingPair{{From: "spine-1", To: "leaf-1"}})
	fakeRedis(t, respBulk(raw))
	pairs, err := FetchRoutingDirection(context.Background())
	if err != nil {
		t.Fatalf("FetchRoutingDirection: %v", err)
	}
	if len(pairs) != 1 || pairs[0].From != "spine-1" || pairs[0].To != "leaf-1" {
		t.Errorf("got %#v, want one spine-1→leaf-1 pair", pairs)
	}
}

func TestFetchIfIndexMapParsesAPublishedMap(t *testing.T) {
	raw := mustJSON(t, map[string]map[string]string{
		"leaf-1": {"12": "Ethernet12"},
	})
	fakeRedis(t, respBulk(raw))
	m, err := FetchIfIndexMap(context.Background())
	if err != nil {
		t.Fatalf("FetchIfIndexMap: %v", err)
	}
	if m["leaf-1"]["12"] != "Ethernet12" {
		t.Errorf("got %#v, want leaf-1/12 → Ethernet12", m)
	}
}

func TestFetchWANCircuitsParsesAPublishedList(t *testing.T) {
	raw := mustJSON(t, []EchoTarget{{
		CircuitID: "c-1", Tenant: "acme", LocalDevice: "edge-1", LocalIf: "Ethernet1",
		LocalAddr: "10.0.0.1", RemoteDevice: "edge-2", RemoteIf: "Ethernet1", RemoteAddr: "10.0.0.2",
	}})
	fakeRedis(t, respBulk(raw))
	tg, err := FetchWANCircuits(context.Background())
	if err != nil {
		t.Fatalf("FetchWANCircuits: %v", err)
	}
	if len(tg) != 1 || tg[0].CircuitID != "c-1" || tg[0].RemoteAddr != "10.0.0.2" {
		t.Errorf("got %#v, want the one published circuit", tg)
	}
}

// ---- (d) a payload that will not decode is corruption, not absence --------

func TestTheFourDependencyReadsReportAnUndecodablePayload(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		call func(context.Context) error
	}{
		{"FetchIfAddrMap", ifAddrKey, func(ctx context.Context) error { _, err := FetchIfAddrMap(ctx); return err }},
		{"FetchRoutingDirection", routingDirKey, func(ctx context.Context) error { _, err := FetchRoutingDirection(ctx); return err }},
		{"FetchIfIndexMap", ifIndexKey, func(ctx context.Context) error { _, err := FetchIfIndexMap(ctx); return err }},
		{"FetchWANCircuits", wanCircuitsKey, func(ctx context.Context) error { _, err := FetchWANCircuits(ctx); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeRedis(t, respBulk("{not json"))
			err := tc.call(context.Background())
			if err == nil {
				t.Fatal("a corrupt payload was swallowed — the reader answers as though the publisher had published nothing")
			}
			if !containsStr(err.Error(), tc.key) {
				t.Errorf("the error does not name the key it could not decode: %v", err)
			}
		})
	}
}

// ---- the unconfigured deployment stays a distinguishable sentinel ---------

// A deployment with no sharing channel at all runs no collector on the other
// end, so "nothing is published" is TRUE of it. Every caller's disposition hangs
// off telling that apart from a channel it could not reach, so the sentinel is
// asserted here rather than left to each caller.
func TestTheFourDependencyReadsReturnTheSentinelWithNoChannelConfigured(t *testing.T) {
	t.Setenv("REDIS_HOST", "")
	ctx := context.Background()
	checks := map[string]error{}
	_, checks["FetchIfAddrMap"] = FetchIfAddrMap(ctx)
	_, checks["FetchRoutingDirection"] = FetchRoutingDirection(ctx)
	_, checks["FetchIfIndexMap"] = FetchIfIndexMap(ctx)
	_, checks["FetchWANCircuits"] = FetchWANCircuits(ctx)
	for name, err := range checks {
		if !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s: err = %v, want ErrNotConfigured — an unconfigured channel must stay distinguishable from a dead one", name, err)
		}
	}
}

// ---- helpers --------------------------------------------------------------

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// containsStr avoids pulling strings in for one call in this file.
func containsStr(hay, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
