package collectors

import (
	"context"
	"sync"
	"time"
)

// GNMI is a gRPC-based streaming/poll collector for OpenConfig YANG paths.
// Replace the body of Run with openconfig/gnmi client wiring when ready.
type GNMI struct {
	mu     sync.RWMutex
	status Status
}

func NewGNMI() *GNMI {
	return &GNMI{status: Status{Name: "gnmi", Healthy: true}}
}

func (g *GNMI) Name() string { return "gnmi" }

func (g *GNMI) Run(ctx context.Context) error {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			g.mu.Lock()
			g.status.LastTick = t.UTC()
			g.mu.Unlock()
		}
	}
}

func (g *GNMI) Status() Status {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.status
}
