// Package collectors orchestrates per-protocol metric collectors.
//
// Each Collector implementation is a self-contained goroutine that reads
// the device inventory, polls or subscribes to its target, and emits
// metrics onto a shared bus. The Pool tracks which collectors are
// currently enabled and surfaces their health for /admin/health.
package collectors

import (
	"context"
	"sync"
	"time"
)

// Collector is the contract every protocol-specific collector implements.
type Collector interface {
	Name() string
	Run(ctx context.Context) error
	Status() Status
}

// Status is a snapshot of a collector's recent behaviour, exposed via API.
type Status struct {
	Name string `json:"name"`
	// Kind separates transport/protocol collectors (snmp/gnmi/netconf), shown
	// in the Collectors tab, from feature collectors like tunnel discovery that
	// have their own views. "protocol" | "discovery".
	Kind           string    `json:"kind,omitempty"`
	Enabled        bool      `json:"enabled"`
	Healthy        bool      `json:"healthy"`
	LastTick       time.Time `json:"last_tick,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	Targets        int       `json:"targets"`
	Reachable      int       `json:"reachable"`
	LastPollMillis int64     `json:"last_poll_ms,omitempty"`
}

// Pool holds the configured collectors and runs the enabled ones.
type Pool struct {
	mu         sync.RWMutex
	collectors map[string]Collector
	enabled    map[string]bool
}

// NewPool builds the collector set. targets supplies the live device
// inventory each collector polls (pass nil for none).
func NewPool(targets TargetFunc) *Pool {
	p := &Pool{
		collectors: make(map[string]Collector),
		enabled:    make(map[string]bool),
	}
	p.register(NewSNMP(targets))
	p.register(NewGNMI(targets))
	p.register(NewNETCONF(targets))
	p.register(NewTunnels(targets))
	p.register(NewSNMPMetrics(targets))
	return p
}

func (p *Pool) register(c Collector) {
	p.collectors[c.Name()] = c
}

// Enable toggles a named collector. Must be called before Start.
func (p *Pool) Enable(name string, on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.enabled[name] = on
}

// Start launches goroutines for each enabled collector.
func (p *Pool) Start(ctx context.Context) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for name, c := range p.collectors {
		if !p.enabled[name] {
			continue
		}
		go func(c Collector) {
			_ = c.Run(ctx)
		}(c)
	}
}

// Status returns a snapshot of all registered collectors.
func (p *Pool) Status() []Status {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]Status, 0, len(p.collectors))
	for name, c := range p.collectors {
		s := c.Status()
		s.Enabled = p.enabled[name]
		out = append(out, s)
	}
	return out
}

// Health is a compact summary suitable for /admin/health.
func (p *Pool) Health() map[string]bool {
	out := make(map[string]bool, len(p.collectors))
	for _, s := range p.Status() {
		out[s.Name] = s.Healthy
	}
	return out
}
