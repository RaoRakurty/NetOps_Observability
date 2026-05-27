package collectors

import (
	"context"
	"sync"
	"time"
)

// NETCONF collector — SSH-based RPC against YANG models. Implement Run with
// scrapli-netconf or a custom SSH session when the integration is needed.
type NETCONF struct {
	mu     sync.RWMutex
	status Status
}

func NewNETCONF() *NETCONF {
	return &NETCONF{status: Status{Name: "netconf", Healthy: true}}
}

func (n *NETCONF) Name() string { return "netconf" }

func (n *NETCONF) Run(ctx context.Context) error {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			n.mu.Lock()
			n.status.LastTick = t.UTC()
			n.mu.Unlock()
		}
	}
}

func (n *NETCONF) Status() Status {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.status
}
