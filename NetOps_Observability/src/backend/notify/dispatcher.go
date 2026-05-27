// Package notify fans alert events out to one or more channels.
//
// Channels are kept tiny and self-contained so adding a new destination is
// just a matter of implementing the Channel interface and registering it.
package notify

import (
	"log"
	"sync"

	"netops/backend/models"
)

// Channel is the contract for an outbound notification destination.
type Channel interface {
	Name() string
	Send(a models.Alert) error
}

// Dispatcher holds the registered channels and forwards alerts to each.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []Channel
}

func NewDispatcher() *Dispatcher { return &Dispatcher{} }

func (d *Dispatcher) Register(c Channel) {
	if c == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, c)
}

// Dispatch sends the alert to all registered channels concurrently.
// Channel errors are logged but never returned — alert delivery should
// never block the evaluation loop.
func (d *Dispatcher) Dispatch(a models.Alert) {
	d.mu.RLock()
	channels := make([]Channel, len(d.channels))
	copy(channels, d.channels)
	d.mu.RUnlock()

	for _, c := range channels {
		go func(c Channel) {
			if err := c.Send(a); err != nil {
				log.Printf("notify %s: %v", c.Name(), err)
			}
		}(c)
	}
}
