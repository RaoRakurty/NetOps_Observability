// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// bgpls_integration_test.go — end-to-end exercise of the BGP-LS collector against
// a FAKE BGP-LS peer that speaks the real wire protocol. Because no lab/CI device
// originates BGP-LS, this in-process peer does the BGP handshake and streams a
// synthetic IS-IS fabric LSDB (the "fake LSDB"), so the collector's full pipeline
// — TCP session → OPEN/KEEPALIVE → UPDATE framing → MP_REACH parse → NLRI decode
// → node↔link join → buildLinks — runs on genuine wire bytes, deterministically.
//
// It complements the byte-fixture unit tests (which test the parser in isolation)
// and the live lab validation (which proved session/AF negotiation against real
// Arista BGP but could not feed NLRI). This closes the "decode never ran on a live
// session" gap without needing a producer-capable router.

// fakeBGPLSPeer accepts ONE inbound session from the collector, completes the
// minimal handshake, streams the given UPDATE bodies, then answers keepalives
// until the connection closes. Reuses the collector's own framing (writeBGP /
// readBGP / buildOpen), so the bytes on the wire are exactly what it understands.
func fakeBGPLSPeer(t *testing.T, ln net.Listener, updates [][]byte, ready *sync.WaitGroup) {
	conn, err := ln.Accept()
	if err != nil {
		return // listener closed (test over)
	}
	defer conn.Close()

	// 1. read the collector's OPEN.
	if typ, _, err := readBGP(conn, 90); err != nil || typ != msgOpen {
		t.Errorf("fake peer: expected collector OPEN, got type=%d err=%v", typ, err)
		return
	}
	// 2. send our OPEN + KEEPALIVE (iBGP AS 65000, link-state cap via buildOpen).
	if err := writeBGP(conn, msgOpen, buildOpen(65000, [4]byte{10, 0, 0, 99}, 90)); err != nil {
		return
	}
	if err := writeBGP(conn, msgKeepalive, nil); err != nil {
		return
	}
	// 3. read the collector's KEEPALIVE (it sends one on reaching OpenConfirm).
	if _, _, err := readBGP(conn, 90); err != nil {
		return
	}
	// 4. stream the synthetic LSDB.
	for _, u := range updates {
		if err := writeBGP(conn, msgUpdate, u); err != nil {
			return
		}
	}
	ready.Done() // all UPDATEs sent — the collector can now decode them

	// 5. hold the session open, draining the collector's periodic keepalives.
	for {
		if _, _, err := readBGP(conn, 90); err != nil {
			return
		}
	}
}

// fabricLSDB builds a synthetic IS-IS L2 fabric as BGP-LS UPDATEs: 3 nodes
// (spine1 + leaf1 + leaf2, each a Node NLRI carrying its hostname) and 2 links
// (spine1→leaf1, spine1→leaf2). Mirrors the real clos lab so a Redis/UI seed built
// the same way resolves against inventory hostnames.
func fabricLSDB() [][]byte {
	sysSpine1 := []byte{0, 0, 0, 0, 0, 1}
	sysLeaf1 := []byte{0, 0, 0, 0, 0, 0x11}
	sysLeaf2 := []byte{0, 0, 0, 0, 0, 0x12}
	descSpine1 := isisNodeDescSubs(65000, sysSpine1)
	descLeaf1 := isisNodeDescSubs(65000, sysLeaf1)
	descLeaf2 := isisNodeDescSubs(65000, sysLeaf2)

	node := func(subs []byte, name string) []byte {
		return updateBody(lsNLRIWrap(nlriTypeNode, nodeNLRIValue(2, subs)), tlv16(tlvNodeName, []byte(name)), true)
	}
	link := func(local, remote, lIP, rIP []byte) []byte {
		return updateBody(lsNLRIWrap(nlriTypeLink, linkNLRIValue(2, local, remote, lIP, rIP)), nil, true)
	}
	return [][]byte{
		node(descSpine1, "spine1"),
		node(descLeaf1, "leaf1"),
		node(descLeaf2, "leaf2"),
		link(descSpine1, descLeaf1, []byte{10, 0, 1, 0}, []byte{10, 0, 1, 1}),
		link(descSpine1, descLeaf2, []byte{10, 0, 2, 0}, []byte{10, 0, 2, 1}),
	}
}

func TestBGPLSCollectorEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var sent sync.WaitGroup
	sent.Add(1)
	go fakeBGPLSPeer(t, ln, fabricLSDB(), &sent)

	c := NewBGPLS().(*bgplsCollector)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Drive the collector's real session loop against the fake peer.
	go func() { _ = c.session(ctx, bgplsPeer{addr: ln.Addr().String(), peerAS: 65000}) }()

	// Wait until the peer has streamed the LSDB, then poll buildLinks until the
	// collector has decoded both links (or time out).
	sent.Wait()
	var links []LLDPNeighbor
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.RLock()
		links = c.buildLinks()
		c.mu.RUnlock()
		if len(links) >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if len(links) != 2 {
		t.Fatalf("expected 2 decoded fabric links, got %d: %+v", len(links), links)
	}
	// Every link must be bgp_ls, IS-IS L2, with both endpoints resolved to the
	// node-name carried in the Node NLRI (the node↔link join working over the wire).
	byTarget := map[string]LLDPNeighbor{}
	for _, l := range links {
		if l.Proto != "bgp_ls" || l.IGP != "isis-l2" {
			t.Errorf("link proto/igp = %q/%q, want bgp_ls/isis-l2", l.Proto, l.IGP)
		}
		if l.LocalName != "spine1" {
			t.Errorf("local name = %q, want spine1 (hostname from Node NLRI)", l.LocalName)
		}
		byTarget[l.RemSysName] = l
	}
	for _, want := range []string{"leaf1", "leaf2"} {
		l, ok := byTarget[want]
		if !ok {
			t.Fatalf("missing decoded link spine1→%s; got %+v", want, links)
		}
		if l.LocalPort == "" || l.RemPort == "" {
			t.Errorf("link spine1→%s missing interface addrs: local=%q rem=%q", want, l.LocalPort, l.RemPort)
		}
	}
}
