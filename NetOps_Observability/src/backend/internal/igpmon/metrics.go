package igpmon

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// metrics.go — the module's Prometheus surface (§10: every service emits
// metrics). One counter, two labels: which protocol was asked about and which
// operation served it.

// Metrics holds the module's counters. The zero value is not usable; build it
// with NewMetrics.
type Metrics struct {
	mu      sync.Mutex
	queries map[[2]string]uint64 // (proto, op) → count
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics {
	return &Metrics{queries: map[[2]string]uint64{}}
}

// Query records one served read.
func (m *Metrics) Query(proto Proto, op string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.queries == nil {
		m.queries = map[[2]string]uint64{}
	}
	m.queries[[2]string{string(proto), op}]++
}

// Write emits the exposition text at scrape time. Labels are written in sorted
// order so a scrape is byte-stable.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	keys := make([][2]string, 0, len(m.queries))
	for k := range m.queries {
		keys = append(keys, k)
	}
	vals := make(map[[2]string]uint64, len(m.queries))
	for k, v := range m.queries {
		vals[k] = v
	}
	m.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	fmt.Fprintf(w, "# HELP netops_igpmon_queries_total IGP (OSPF/IS-IS) monitoring reads served, by protocol and operation.\n")
	fmt.Fprintf(w, "# TYPE netops_igpmon_queries_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(w, "netops_igpmon_queries_total{proto=%q,op=%q} %d\n", k[0], k[1], vals[k])
	}
}
