// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// trie.go — a compact bitwise radix trie for longest-prefix-match IP→entry lookup
// (#81 P1, the resolver spine). Stdlib only (net/netip); IPv4 and IPv6 kept in
// separate roots. Lookup is O(address-bits) and the structure is a few bytes per
// node, so millions of prefixes resolve fast at low memory — the whole reason the
// app-ID problem is a cheap lookup, not payload analysis.

import "net/netip"

type trieNode struct {
	child [2]*trieNode
	vals  []CatalogEntry // entries whose prefix ends exactly at this node
}

// prefixTrie holds an IPv4 and an IPv6 radix trie.
type prefixTrie struct {
	root4 *trieNode
	root6 *trieNode
	n     int
}

func newPrefixTrie() *prefixTrie {
	return &prefixTrie{root4: &trieNode{}, root6: &trieNode{}}
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func bitAt(b []byte, i int) int {
	return int((b[i/8] >> (7 - uint(i%8))) & 1)
}

// insert adds an entry under its (masked) prefix. Invalid prefixes are ignored.
func (t *prefixTrie) insert(p netip.Prefix, e CatalogEntry) {
	if !p.IsValid() {
		return
	}
	p = p.Masked()
	addr := p.Addr()
	root := t.root4
	if addr.Is6() {
		root = t.root6
	}
	bytes := addrBytes(addr)
	n := root
	for i := 0; i < p.Bits(); i++ {
		b := bitAt(bytes, i)
		if n.child[b] == nil {
			n.child[b] = &trieNode{}
		}
		n = n.child[b]
	}
	n.vals = append(n.vals, e)
	t.n++
}

// lookup returns the entries of the longest prefix that contains addr (nil if none).
func (t *prefixTrie) lookup(addr netip.Addr) []CatalogEntry {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return nil
	}
	root, nbits := t.root4, 32
	if addr.Is6() {
		root, nbits = t.root6, 128
	}
	bytes := addrBytes(addr)
	n := root
	var best []CatalogEntry
	if len(n.vals) > 0 {
		best = n.vals
	}
	for i := 0; i < nbits; i++ {
		n = n.child[bitAt(bytes, i)]
		if n == nil {
			break
		}
		if len(n.vals) > 0 {
			best = n.vals // deepest match wins (longest prefix)
		}
	}
	return best
}
