package parsercov

// cache.go — the mining-result cache.
//
// A mining run scans up to PARSERCOV_MAX_LINES documents out of OpenSearch. It
// is not a query an operator should be able to re-issue on every keystroke, and
// the propose route needs to resolve a template_id the client received from an
// EARLIER run. Both wants are served by one small, BOUNDED store.
//
// BOUNDED IS THE WHOLE POINT (§9: all queues are bounded; no unbounded growth).
// The key space is caller-derived — one entry per (scope, days, lane) — so an
// unbounded map is a memory hole any authenticated caller could walk. Three
// limits, all enforced on every write:
//
//	entries : maxCacheEntries, evicted OLDEST-FIRST by insertion order
//	age     : cacheTTL, checked on read AND swept on write
//	content : the miner already caps groups/devices/sample size
//
// Insertion-ordered eviction (rather than LRU) is deliberate: it needs no
// per-read bookkeeping, so a read never mutates ordering, and the worst case is
// re-mining a window an operator is still looking at — a cost, not a defect.

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const (
	// cacheTTL is how long a mined window is reused. Ten minutes: long enough
	// that paging the table and drafting a proposal reuse one scan, short
	// enough that a lane that just started emitting shows up while the
	// operator is still watching.
	cacheTTL = 10 * time.Minute
	// maxCacheEntries bounds the number of live mining results. Each entry is
	// at most MaxGroups items, so the ceiling is a constant, not a function of
	// traffic or of how many principals call.
	maxCacheEntries = 64
)

// cacheEntry is one completed mining run. The FULL item list is retained (it
// is already bounded by the miner's group cap) and the per-request `limit` is
// applied at render time, so two callers asking for different page sizes share
// one scan and a propose lookup can resolve an id past the first page.
type cacheEntry struct {
	key    string
	run    runResult
	byID   map[string]Item
	stored time.Time
}

// miningCache is a bounded, TTL'd, insertion-ordered store. Safe for
// concurrent use — the handler set is shared across requests.
type miningCache struct {
	mu    sync.Mutex
	items map[string]*cacheEntry
	order []string
	ttl   time.Duration
	max   int
	now   func() time.Time
}

func newMiningCache(now func() time.Time) *miningCache {
	return &miningCache{
		items: make(map[string]*cacheEntry, maxCacheEntries),
		ttl:   cacheTTL,
		max:   maxCacheEntries,
		now:   now,
	}
}

// cacheKey identifies one mining run: the caller's RESOLVED scope (index
// pattern plus the marshalled tenant clause — not the tenant id, so two
// principals in one tenant with different device visibility can never share an
// entry) plus the window and lane.
//
// Hashed rather than stored verbatim so the key length is fixed and no device
// identifier is retained in a map key.
func cacheKey(index string, clause []byte, days int, lane Lane) string {
	h := sha256.New()
	h.Write([]byte(index))
	h.Write([]byte{0})
	h.Write(clause)
	h.Write([]byte{0})
	h.Write([]byte(itoa(days)))
	h.Write([]byte{0})
	h.Write([]byte(lane))
	return hex.EncodeToString(h.Sum(nil))
}

// get returns a live entry, or nil. An expired entry is dropped on the way
// out, so a stale result can never be served once.
func (c *miningCache) get(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[key]
	if !ok {
		return nil
	}
	if c.now().Sub(e.stored) >= c.ttl {
		c.removeLocked(key)
		return nil
	}
	return e
}

// put stores a result, sweeping expired entries first and then evicting the
// oldest until the size bound holds.
func (c *miningCache) put(key string, run runResult) {
	byID := make(map[string]Item, len(run.All))
	for _, it := range run.All {
		byID[it.TemplateID] = it
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	// Sweep expired entries. Walking `order` (not the map) keeps the traversal
	// deterministic and the slice compaction in one pass.
	kept := c.order[:0]
	for _, k := range c.order {
		e, ok := c.items[k]
		if !ok {
			continue
		}
		if now.Sub(e.stored) >= c.ttl && k != key {
			delete(c.items, k)
			continue
		}
		kept = append(kept, k)
	}
	c.order = kept
	if _, exists := c.items[key]; exists {
		c.removeLocked(key)
	}
	for len(c.order) >= c.max {
		c.removeLocked(c.order[0])
	}
	c.items[key] = &cacheEntry{key: key, run: run, byID: byID, stored: now}
	c.order = append(c.order, key)
}

// removeLocked drops one entry and its order slot. Caller holds the mutex.
func (c *miningCache) removeLocked(key string) {
	delete(c.items, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// size reports the live entry count (test seam; the bound is an assertion, not
// a hope).
func (c *miningCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}
