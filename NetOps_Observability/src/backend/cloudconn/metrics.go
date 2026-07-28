package cloudconn

// cloud_connectors_metrics.go — Wave 4 #13: per-provider-exchange metrics for
// the Identity Broker, exposed on the existing /metrics Prometheus surface
// (scraped by VictoriaMetrics via vmscrape.yml, job netops-api).
//
// Counters are per (provider, outcome) with a small fixed outcome vocabulary —
// auth_success / auth_fail / throttled / api_error / deferred — plus a
// latency sum/count per provider (fresh mints only; cache hits are counted
// separately and cost no provider round-trip). Everything is in-memory,
// monotonic since process start, and label-bounded (§9: 3 providers × 5
// outcomes — no unbounded label sets, no tenant/connector labels: those are
// per-tenant DATA, and /metrics is an unauthenticated platform surface).

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Exchange outcome tokens (stable — dashboards/alerts key on them).
const (
	exOutcomeSuccess   = "auth_success"
	exOutcomeAuthFail  = "auth_fail"
	exOutcomeThrottled = "throttled"
	exOutcomeAPIError  = "api_error"
	exOutcomeDeferred  = "deferred"
)

// ExchangeMetrics aggregates the broker's provider-exchange telemetry.
type ExchangeMetrics struct {
	mu        sync.Mutex
	counts    map[string]map[string]uint64 // provider → outcome → n
	latSum    map[string]float64           // provider → seconds (fresh mints)
	latCount  map[string]uint64
	cacheHits map[string]uint64 // provider → cache-served tokens
}

func NewExchangeMetrics() *ExchangeMetrics {
	return &ExchangeMetrics{
		counts:    map[string]map[string]uint64{},
		latSum:    map[string]float64{},
		latCount:  map[string]uint64{},
		cacheHits: map[string]uint64{},
	}
}

// exchangeOutcome maps an exchange result onto the fixed outcome vocabulary.
func exchangeOutcome(err error) string {
	if err == nil {
		return exOutcomeSuccess
	}
	if errors.Is(err, ErrPlatformCredentialsMissing) ||
		errors.Is(err, ErrWorkloadAssertionMissing) ||
		errors.Is(err, ErrProviderExchangeDeferred) {
		return exOutcomeDeferred
	}
	var xe *ExchangeError
	if errors.As(err, &xe) {
		switch xe.Code {
		case "denied":
			return exOutcomeAuthFail
		case "throttled":
			return exOutcomeThrottled
		}
	}
	return exOutcomeAPIError
}

// recordExchange records one FRESH provider exchange (outcome + latency).
func (m *ExchangeMetrics) recordExchange(provider Provider, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	p := string(provider)
	outcome := exchangeOutcome(err)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts[p] == nil {
		m.counts[p] = map[string]uint64{}
	}
	m.counts[p][outcome]++
	m.latSum[p] += elapsed.Seconds()
	m.latCount[p]++
}

// recordCacheHit records a token served from the broker cache (no provider call).
func (m *ExchangeMetrics) recordCacheHit(provider Provider) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheHits[string(provider)]++
}

// write emits the Prometheus text exposition (called from /metrics).
// Write renders the Prometheus exposition lines.
func (m *ExchangeMetrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_cloudconn_exchange_total Cloud connector credential exchanges by provider and outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_cloudconn_exchange_total counter\n")
	providers := make([]string, 0, len(m.counts))
	for p := range m.counts {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	for _, p := range providers {
		outcomes := make([]string, 0, len(m.counts[p]))
		for o := range m.counts[p] {
			outcomes = append(outcomes, o)
		}
		sort.Strings(outcomes)
		for _, o := range outcomes {
			fmt.Fprintf(w, "netops_cloudconn_exchange_total{provider=%q,outcome=%q} %d\n", p, o, m.counts[p][o])
		}
	}
	fmt.Fprintf(w, "# HELP netops_cloudconn_exchange_latency_seconds Total latency of fresh provider credential exchanges.\n")
	fmt.Fprintf(w, "# TYPE netops_cloudconn_exchange_latency_seconds summary\n")
	latProviders := make([]string, 0, len(m.latCount))
	for p := range m.latCount {
		latProviders = append(latProviders, p)
	}
	sort.Strings(latProviders)
	for _, p := range latProviders {
		fmt.Fprintf(w, "netops_cloudconn_exchange_latency_seconds_sum{provider=%q} %.6f\n", p, m.latSum[p])
		fmt.Fprintf(w, "netops_cloudconn_exchange_latency_seconds_count{provider=%q} %d\n", p, m.latCount[p])
	}
	if len(m.cacheHits) > 0 {
		fmt.Fprintf(w, "# HELP netops_cloudconn_exchange_cache_hits_total Broker tokens served from cache (no provider call).\n")
		fmt.Fprintf(w, "# TYPE netops_cloudconn_exchange_cache_hits_total counter\n")
		hitProviders := make([]string, 0, len(m.cacheHits))
		for p := range m.cacheHits {
			hitProviders = append(hitProviders, p)
		}
		sort.Strings(hitProviders)
		for _, p := range hitProviders {
			fmt.Fprintf(w, "netops_cloudconn_exchange_cache_hits_total{provider=%q} %d\n", p, m.cacheHits[p])
		}
	}
}
