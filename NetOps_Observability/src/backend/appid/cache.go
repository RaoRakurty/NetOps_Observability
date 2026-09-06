// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

// cache.go — a bounded LRU over the global catalog's IP→signals lookup (#81 P4).
//
// The radix trie is already O(address-bits), so this is a SECONDARY lever (the
// design's stance: index first, cache only where it measurably helps). Where it
// helps: flow→app aggregation resolves up to ~1000 destinations per request and
// real traffic is heavily skewed to a few popular destinations — the cache collapses
// those repeats (and NEGATIVELY caches misses, so uncatalogued internal IPs don't
// re-walk the trie every flow). It's tenant-agnostic: it caches only the GLOBAL
// catalog's own signals (vendor IP ranges are the same for everyone); per-tenant
// overrides + NGFW are layered separately and never enter this cache.
//
// The cache lives in the immutable Catalog generation, so a feed reload builds a
// fresh Catalog and the cache resets naturally — no invalidation logic needed.

import (
	"container/list"
	"net/netip"
	"sync"
)

type sigCacheEntry struct {
	key netip.Addr
	val []Signal
}

type sigCache struct {
	mu  sync.Mutex
	cap int
	ll  *list.List
	m   map[netip.Addr]*list.Element
}

func newSigCache(capacity int) *sigCache {
	if capacity <= 0 {
		capacity = 1
	}
	return &sigCache{cap: capacity, ll: list.New(), m: make(map[netip.Addr]*list.Element, capacity)}
}

// get returns (signals, true) on a hit — including a NEGATIVE hit, where val is an
// empty slice (a known miss). (nil, false) means not cached.
func (c *sigCache) get(k netip.Addr) ([]Signal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*sigCacheEntry).val, true
	}
	return nil, false
}

func (c *sigCache) put(k netip.Addr, v []Signal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		c.ll.MoveToFront(e)
		e.Value.(*sigCacheEntry).val = v
		return
	}
	c.m[k] = c.ll.PushFront(&sigCacheEntry{key: k, val: v})
	if c.ll.Len() > c.cap {
		if old := c.ll.Back(); old != nil {
			c.ll.Remove(old)
			delete(c.m, old.Value.(*sigCacheEntry).key)
		}
	}
}
