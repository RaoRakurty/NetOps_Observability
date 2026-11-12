// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aiprovider

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// CallBuckets are the latency buckets (seconds) for provider calls: the stage
// budgets (8 s fast, 15 s strong) and the transport ceiling (60 s) are bounds,
// so each has a bucket edge at or near it.
var CallBuckets = []float64{0.25, 0.5, 1, 2, 4, 8, 15, 30, 60}

// maxCallSeries bounds the {provider,tier,outcome} label space. Providers,
// tiers and outcomes are each closed sets in the caller, so this is a backstop,
// not a working limit; past it observations are counted as dropped.
const maxCallSeries = 512

type callKey struct{ provider, tier, outcome string }

type hist struct {
	counts []atomic.Int64 // len(CallBuckets)+1, the last is +Inf
	sumMs  atomic.Int64
	n      atomic.Int64
}

// Metrics is the provider-call telemetry: netops_ai_provider_call_seconds
// {provider,tier,outcome} and, rendered from the Breaker, the breaker gauges.
// Nil-safe.
type Metrics struct {
	mu      sync.Mutex
	calls   map[callKey]*hist
	dropped atomic.Int64
	breaker *Breaker
	tokens  *tokenCounters // netops_ai_provider_tokens_total (usage.go)
}

// NewMetrics builds the metrics; breaker may be nil.
func NewMetrics(b *Breaker) *Metrics {
	return &Metrics{calls: map[callKey]*hist{}, breaker: b, tokens: &tokenCounters{n: map[tokenKey]int64{}}}
}

// ObserveCall records one provider call (or a skipped one: outcome
// breaker_open with zero seconds).
func (m *Metrics) ObserveCall(provider, tier, outcome string, seconds float64) {
	if m == nil {
		return
	}
	if tier == "" {
		tier = "default"
	}
	k := callKey{provider, tier, outcome}
	m.mu.Lock()
	h := m.calls[k]
	if h == nil {
		if len(m.calls) >= maxCallSeries {
			m.mu.Unlock()
			m.dropped.Add(1)
			return
		}
		h = &hist{counts: make([]atomic.Int64, len(CallBuckets)+1)}
		m.calls[k] = h
	}
	m.mu.Unlock()
	if seconds < 0 {
		seconds = 0
	}
	i := sort.SearchFloat64s(CallBuckets, seconds)
	h.counts[i].Add(1)
	h.sumMs.Add(int64(seconds * 1000))
	h.n.Add(1)
}

// Write renders Prometheus text.
func (m *Metrics) Write(w io.Writer) error {
	if m == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("# HELP netops_ai_provider_call_seconds Model-provider call latency by provider, model tier and outcome (timeout, auth, model_not_found, rate_limited, server_error, empty_response, network, breaker_open, …).\n")
	b.WriteString("# TYPE netops_ai_provider_call_seconds histogram\n")
	m.mu.Lock()
	keys := make([]callKey, 0, len(m.calls))
	for k := range m.calls {
		keys = append(keys, k)
	}
	m.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.provider != c.provider {
			return a.provider < c.provider
		}
		if a.tier != c.tier {
			return a.tier < c.tier
		}
		return a.outcome < c.outcome
	})
	for _, k := range keys {
		m.mu.Lock()
		h := m.calls[k]
		m.mu.Unlock()
		labels := fmt.Sprintf("provider=%q,tier=%q,outcome=%q", k.provider, k.tier, k.outcome)
		var cum int64
		for i, ub := range CallBuckets {
			cum += h.counts[i].Load()
			fmt.Fprintf(&b, "netops_ai_provider_call_seconds_bucket{%s,le=\"%g\"} %d\n", labels, ub, cum)
		}
		cum += h.counts[len(CallBuckets)].Load()
		fmt.Fprintf(&b, "netops_ai_provider_call_seconds_bucket{%s,le=\"+Inf\"} %d\n", labels, cum)
		fmt.Fprintf(&b, "netops_ai_provider_call_seconds_sum{%s} %g\n", labels, float64(h.sumMs.Load())/1000)
		fmt.Fprintf(&b, "netops_ai_provider_call_seconds_count{%s} %d\n", labels, h.n.Load())
	}
	b.WriteString("# HELP netops_ai_provider_call_series_dropped_total Provider-call observations dropped because the label space was full.\n")
	b.WriteString("# TYPE netops_ai_provider_call_series_dropped_total counter\n")
	fmt.Fprintf(&b, "netops_ai_provider_call_series_dropped_total %d\n", m.dropped.Load())
	if err := m.writeTokens(&b); err != nil {
		return err
	}

	snap := m.breaker.Snapshot()
	b.WriteString("# HELP netops_ai_provider_breaker_state Workspace×provider circuit breakers in each state (closed, open, half_open). Unlisted pairs are closed.\n")
	b.WriteString("# TYPE netops_ai_provider_breaker_state gauge\n")
	for _, p := range snap.Providers {
		for _, s := range States {
			fmt.Fprintf(&b, "netops_ai_provider_breaker_state{provider=%q,state=%q} %d\n", p, s.String(), snap.States[p][s])
		}
	}
	b.WriteString("# HELP netops_ai_provider_breaker_transitions_total Circuit-breaker state changes by provider and the state entered.\n")
	b.WriteString("# TYPE netops_ai_provider_breaker_transitions_total counter\n")
	for _, p := range snap.Providers {
		for _, s := range States {
			fmt.Fprintf(&b, "netops_ai_provider_breaker_transitions_total{provider=%q,to=%q} %d\n", p, s.String(), snap.Transitions[p][s])
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
