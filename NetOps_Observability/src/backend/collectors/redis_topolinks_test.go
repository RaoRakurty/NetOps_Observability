// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// redis_topolinks_test.go — tracker 290, the fold half.
//
// FetchTopologyLinks folded every outcome into one
// `if err != nil || raw == "" { continue }`, so a dead discovery channel came
// back as an EMPTY neighbour set with a NIL error. That is not "we could not
// read it": it is the sentence "no device on this estate is next to anything",
// asserted with confidence, to every caller on the topology read path.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func oneNeighbourBatch(t *testing.T, local, remote string) string {
	t.Helper()
	raw, err := json.Marshal([]LLDPNeighbor{{
		LocalDevice: local, LocalName: local, LocalPort: "Ethernet1",
		RemSysName: remote, RemPort: "Ethernet2", Proto: "lldp",
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return respBulk(string(raw))
}

// A channel that dies part-way through the protocol keys must be REPORTED, and
// what was read before it died must still come back so a caller that can render
// a partial map beside a banner has the material for it.
func TestFetchTopologyLinksReportsABrokenChannel(t *testing.T) {
	fakeRedis(t,
		oneNeighbourBatch(t, "spine-1", "leaf-1"), // GET lldp
		"", // GET cdp: the connection dies
	)
	links, err := FetchTopologyLinks(context.Background())
	if err == nil {
		t.Fatalf("a dead discovery channel returned a nil error with %d links — the topology read path is told the estate has no adjacencies", len(links))
	}
	if !errors.Is(err, errRedisTransport) {
		t.Errorf("a dead connection was not classified as a transport failure: %v", err)
	}
	if !strings.Contains(err.Error(), "2 of 3 protocol keys") {
		t.Errorf("the error does not say how many protocol keys went unread: %v", err)
	}
	if len(links) != 1 {
		t.Errorf("the adjacency that WAS read came back as %d links, want 1 — a partial read is still evidence", len(links))
	}
}

// An absent or empty per-protocol key is a collector that is off. That is a true
// statement about the protocol and must stay a non-error, or every deployment
// running LLDP alone would raise a banner forever.
func TestFetchTopologyLinksTreatsAnAbsentKeyAsACollectorBeingOff(t *testing.T) {
	fakeRedis(t,
		oneNeighbourBatch(t, "spine-1", "leaf-1"), // lldp
		"$-1\r\n",    // cdp: nil bulk (never published)
		"$0\r\n\r\n", // bgp-ls: empty
	)
	links, err := FetchTopologyLinks(context.Background())
	if err != nil {
		t.Fatalf("an unpublished protocol key was reported as a failure: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("got %d links, want the 1 LLDP adjacency", len(links))
	}
}

// A payload that will not decode is a CORRUPT record, not an absent one. It used
// to be dropped without a word, turning a corrupt LLDP blob into "no LLDP
// adjacency exists" (§10).
func TestFetchTopologyLinksReportsAnUndecodablePayload(t *testing.T) {
	fakeRedis(t,
		respBulk("{not json"),                     // lldp: corrupt
		oneNeighbourBatch(t, "spine-1", "leaf-1"), // cdp: fine
		"$-1\r\n", // bgp-ls: absent
	)
	links, err := FetchTopologyLinks(context.Background())
	if err == nil {
		t.Fatal("a corrupt neighbour record was swallowed — the protocol reads as having reported nothing")
	}
	if !strings.Contains(err.Error(), topoLinksKeyLLDP) {
		t.Errorf("the error does not name the unreadable key: %v", err)
	}
	if len(links) != 1 {
		t.Errorf("got %d links, want the 1 adjacency the readable protocol did publish", len(links))
	}
}

// No sharing channel at all is a deployment that runs no discovery collector.
// The sentinel is how a read path tells that apart from a channel it cannot
// reach, and every caller's banner hangs off the difference.
func TestFetchTopologyLinksWithNoChannelConfiguredIsASentinel(t *testing.T) {
	t.Setenv("REDIS_HOST", "")
	_, err := FetchTopologyLinks(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured — an unconfigured channel must be distinguishable from a dead one", err)
	}
}
