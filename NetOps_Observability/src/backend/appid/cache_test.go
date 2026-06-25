package appid

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestSigCache_LRUEvictAndNegative(t *testing.T) {
	c := newSigCache(2)
	a := netip.MustParseAddr("1.1.1.1")
	b := netip.MustParseAddr("2.2.2.2")
	d := netip.MustParseAddr("3.3.3.3")

	c.put(a, []Signal{{App: "A"}})
	c.put(b, nil) // negative cache: a known miss
	if v, ok := c.get(b); !ok || len(v) != 0 {
		t.Fatalf("negative entry should hit with empty slice, got %+v ok=%v", v, ok)
	}
	// touch a so b is the LRU, then insert d → evicts b
	c.get(a)
	c.put(d, []Signal{{App: "D"}})
	if _, ok := c.get(b); ok {
		t.Fatal("b should have been evicted")
	}
	if v, ok := c.get(a); !ok || v[0].App != "A" {
		t.Fatalf("a should survive, got %+v ok=%v", v, ok)
	}
}

func TestCatalog_CacheConsistency(t *testing.T) {
	// a cached lookup must return the same result as an uncached one.
	es, _ := ParseM365([]byte(`[{"serviceArea":"Exchange","ips":["13.107.6.152/31"]}]`))
	c := NewCatalog(es)
	ip := netip.MustParseAddr("13.107.6.153")
	first := c.SignalsFor(ip)  // miss → trie + cache
	second := c.SignalsFor(ip) // hit
	if len(first) != 1 || len(second) != 1 || first[0].App != second[0].App {
		t.Fatalf("cached result diverged: %+v vs %+v", first, second)
	}
	miss := netip.MustParseAddr("8.8.8.8")
	if len(c.SignalsFor(miss)) != 0 || len(c.SignalsFor(miss)) != 0 {
		t.Fatal("a miss must stay a miss (negative cache)")
	}
}

// Demonstrates the cache win on a skewed workload (few hot destinations), the
// flow→app case. Run: go test -bench BenchmarkSignalsFor ./appid/
func BenchmarkSignalsFor_HotSet(b *testing.B) {
	var es []CatalogEntry
	for i := 0; i < 5000; i++ {
		es = append(es, ipCatalogEntry(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), "App", "x"))
	}
	c := NewCatalog(es)
	hot := []netip.Addr{
		netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.1.5"),
		netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.2.5"),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.SignalsFor(hot[i%len(hot)])
	}
}
