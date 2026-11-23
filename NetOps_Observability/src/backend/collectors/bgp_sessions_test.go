// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"errors"
	"testing"
)

// Tracker 436: the BGP4-MIB sessions and the IF-MIB ifType the WAN rule reads.

// ipVal / intVal: the package's BER test helpers (sdwan_overlay_test.go).

func TestBGPSessionReadingJoinsLocalAddressesToThePeers(t *testing.T) {
	var r bgpSessionReading
	r.localAS = 65010
	r.noteRemoteAS(map[string]berVal{
		"203.0.113.1": intVal(64500),
		"10.0.0.2":    intVal(65034),
		"0.0.0.0":     intVal(1), // junk index
	})
	got, read := r.sessions(func() (map[string]berVal, error) {
		return map[string]berVal{
			"203.0.113.1": ipVal(203, 0, 113, 2),
			"10.0.0.2":    ipVal(0, 0, 0, 0), // not up: no local address
			"192.0.2.99":  ipVal(192, 0, 2, 1),
		}, nil
	})
	if !read || got.LocalAS != 65010 || len(got.Peers) != 2 {
		t.Fatalf("read=%v %+v", read, got)
	}
	if p := got.Peers["203.0.113.1"]; p.Local != "203.0.113.2" || p.RemoteAS != 64500 {
		t.Errorf("ISP session: %+v", p)
	}
	if p := got.Peers["10.0.0.2"]; p.Local != "" {
		t.Errorf("a session that is not up has no local address: %+v", p)
	}
}

func TestBGPSessionReadingSaysWhenItIsNotTheWholeAnswer(t *testing.T) {
	// No remote-AS walk (the device did not answer it): not read, keep the last.
	var none bgpSessionReading
	if _, read := none.sessions(func() (map[string]berVal, error) { t.Fatal("walked without peers"); return nil, nil }); read {
		t.Fatal("no remote-AS walk read as the whole answer")
	}
	// BGP4-MIB answered with no peer: read, empty, no local-address walk.
	var empty bgpSessionReading
	empty.noteRemoteAS(map[string]berVal{})
	got, read := empty.sessions(func() (map[string]berVal, error) { t.Fatal("walked without peers"); return nil, nil })
	if !read || len(got.Peers) != 0 {
		t.Fatalf("no peers: read=%v %+v", read, got)
	}
	// The local-address walk failed: not the whole answer.
	var r bgpSessionReading
	r.noteRemoteAS(map[string]berVal{"203.0.113.1": intVal(7)})
	if _, read := r.sessions(func() (map[string]berVal, error) { return nil, errors.New("timeout") }); read {
		t.Fatal("a failed local-address walk read as the whole answer")
	}
}

func TestBGPSessionRowsRetention(t *testing.T) {
	a := bgpSessionRows{}
	tgs := []Target{{ID: "d1"}, {ID: "d2"}}
	s1 := BGPSessions{LocalAS: 65010, Peers: map[string]BGPSession{"203.0.113.1": {Local: "203.0.113.2", RemoteAS: 64500}}}
	got := a.update(tgs, []deviceOutcome{{id: "d1", bgp: s1, bgpRead: true}, {id: "d2", bgpRead: true}})
	if len(got) != 1 || got["d1"].Peers["203.0.113.1"].Local != "203.0.113.2" {
		t.Fatalf("first cycle %v", got)
	}
	// d1 unreachable, then unread: it keeps its sessions.
	got = a.update(tgs, []deviceOutcome{{}, {id: "d2", bgpRead: false}})
	if len(got["d1"].Peers) != 1 {
		t.Fatalf("an unread poll dropped sessions: %v", got)
	}
	// d1 read with no peers: gone. Then it leaves the targets: still gone.
	got = a.update(tgs, []deviceOutcome{{id: "d1", bgpRead: true}, {}})
	if len(got) != 0 {
		t.Fatalf("stale sessions published: %v", got)
	}
}

func TestIfTypeRowsRetainLikeAliases(t *testing.T) {
	a := ifAliasRows{}
	tgs := []Target{{ID: "r1"}}
	got := a.updateWith(tgs, []deviceOutcome{{id: "r1", iftype: map[string]string{"1": "22"}, iftypeRead: true}}, outcomeIfType)
	if got["r1"]["1"] != "22" {
		t.Fatalf("first cycle %v", got)
	}
	got = a.updateWith(tgs, []deviceOutcome{{id: "r1", iftypeRead: false}}, outcomeIfType)
	if got["r1"]["1"] != "22" {
		t.Fatalf("an unread walk dropped the types: %v", got)
	}
	// The selector really is per table: an alias read leaves the types alone.
	got = a.updateWith(tgs, []deviceOutcome{{id: "r1", ifaliasRead: true}}, outcomeIfType)
	if got["r1"]["1"] != "22" {
		t.Fatalf("an alias read touched the ifType rows: %v", got)
	}
}

// The published sessions are re-validated on the way back in (§3: the key is
// writable by anything on the channel): junk addresses go, the rest survive.
func TestFetchBGPSessionsRevalidates(t *testing.T) {
	fakeRedis(t, respBulk(`{"r1":{"local_as":65010,"peers":{"203.0.113.1":{"local":"203.0.113.2","remote_as":64500},"not-an-ip":{"local":"1.2.3.4"},"198.51.100.1":{"local":"<script>","remote_as":7}}},"":{"peers":{}}}`))
	got, err := FetchBGPSessions(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 || len(got["r1"].Peers) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got["r1"].Peers["198.51.100.1"].Local != "" || got["r1"].Peers["203.0.113.1"].Local != "203.0.113.2" {
		t.Fatalf("addresses not re-validated: %+v", got["r1"].Peers)
	}
}

func TestFetchBGPSessionsThreeWayAnswer(t *testing.T) {
	fakeRedis(t, "") // dead channel
	if _, err := FetchBGPSessions(context.Background()); err == nil {
		t.Fatal("a dead channel read as no sessions")
	}
	fakeRedis(t, respBulk("{not json"))
	if _, err := FetchBGPSessions(context.Background()); err == nil {
		t.Fatal("a corrupt payload read as no sessions")
	}
	t.Setenv("REDIS_HOST", "")
	if m, err := FetchBGPSessions(context.Background()); err != nil || len(m) != 0 {
		t.Fatalf("no channel configured: %v %v", m, err)
	}
}

func TestFetchIfTypeMapReportsADeadChannel(t *testing.T) {
	fakeRedis(t, "")
	if _, err := FetchIfTypeMap(context.Background()); err == nil {
		t.Fatal("a dead channel read as no ifTypes")
	}
}
