package collectors

import (
	"context"
	"sync"
	"time"
)

// SNMP is a v2c/v3 polling collector. The scaffold ticks on its configured
// interval and surfaces health, but does not yet open SNMP sessions —
// wire in github.com/gosnmp/gosnmp (or similar) inside Run when ready.
type SNMP struct {
	mu     sync.RWMutex
	status Status
	period time.Duration
}

func NewSNMP() *SNMP {
	return &SNMP{
		status: Status{Name: "snmp", Healthy: true},
		period: 30 * time.Second,
	}
}

func (s *SNMP) Name() string { return "snmp" }

func (s *SNMP) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			s.mu.Lock()
			s.status.LastTick = t.UTC()
			s.status.Healthy = true
			s.mu.Unlock()
			// TODO: walk targets, emit metrics.
		}
	}
}

func (s *SNMP) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}
