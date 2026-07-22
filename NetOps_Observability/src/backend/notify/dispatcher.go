// Package notify fans alert events out to one or more channels.
//
// Channels are kept tiny and self-contained so adding a new destination is
// just a matter of implementing the Channel interface and registering it.
package notify

import (
	"strings"
	"sync"

	"netops/backend/models"
)

// Channel is the contract for an outbound notification destination.
type Channel interface {
	Name() string
	Send(a models.Alert) error
}

// ResolveSender is an optional Channel extension for destinations with
// resolution semantics (e.g. PagerDuty closes the incident it opened for the
// same dedup key). Channels without it simply never learn about resolutions.
type ResolveSender interface {
	SendResolve(a models.Alert) error
}

// Dispatcher holds the registered channels and forwards alerts to each.
//
// Delivery itself is owned by the bounded worker pool in delivery.go (F-22):
// Dispatch/DispatchTo/DispatchResolve ENQUEUE, they no longer spawn a goroutine
// per channel per alert. DispatchToResults stays synchronous — its callers want
// per-channel receipts and already run off the request path.
type Dispatcher struct {
	mu       sync.RWMutex
	channels []Channel
	delivery *delivery
}

func NewDispatcher() *Dispatcher { return &Dispatcher{delivery: newDelivery()} }

func (d *Dispatcher) Register(c Channel) {
	if c == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, c)
}

// Replace swaps the channel sharing the same Name() (or appends it if absent),
// so a channel can be reconfigured at runtime from the admin UI without a
// restart. Pair with Remove to disable a channel.
func (d *Dispatcher) Replace(c Channel) {
	if c == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, ex := range d.channels {
		if ex.Name() == c.Name() {
			d.channels[i] = c
			return
		}
	}
	d.channels = append(d.channels, c)
}

// Remove deletes the channel with the given name (no-op if absent).
func (d *Dispatcher) Remove(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := d.channels[:0]
	for _, c := range d.channels {
		if c.Name() != name {
			out = append(out, c)
		}
	}
	d.channels = out
}

// Dispatch queues the alert for delivery to every registered channel. It never
// blocks the alert evaluation loop and never spawns an unbounded goroutine per
// channel (F-22): sends run on the fixed worker pool, with retries and
// per-channel counters.
func (d *Dispatcher) Dispatch(a models.Alert) {
	for _, c := range d.snapshot() {
		d.delivery.enqueue(sendJob{ch: c, alert: a})
	}
}

// snapshot copies the channel list under the read lock, so delivery never runs
// with the registry lock held.
func (d *Dispatcher) snapshot() []Channel {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Channel, len(d.channels))
	copy(out, d.channels)
	return out
}

// DispatchResolve tells every resolution-capable channel that an alert
// cleared, so destinations like PagerDuty close the incident they opened
// (same dedup key) instead of accumulating stale open incidents forever.
// Channels without ResolveSender are skipped; errors are logged, never block.
func (d *Dispatcher) DispatchResolve(a models.Alert) {
	channels := d.snapshot()

	for _, c := range channels {
		if _, ok := c.(ResolveSender); !ok {
			continue
		}
		d.delivery.enqueue(sendJob{ch: c, alert: a, resolve: true})
	}
}

// Names returns the names of all registered channels — lets the UI present the
// delivery destinations actually configured (so "Send now" only offers real
// channels rather than a hard-coded list).
func (d *Dispatcher) Names() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.channels))
	for _, c := range d.channels {
		out = append(out, c.Name())
	}
	return out
}

// DispatchTo sends the alert only to the named channels (case-insensitive match
// on Channel.Name). An empty/nil selection falls back to Dispatch (all
// channels). Returns the number of channels the alert was dispatched to, so
// callers (e.g. "Send now") can report "delivered to N destination(s)".
func (d *Dispatcher) DispatchTo(a models.Alert, names []string) int {
	if len(names) == 0 {
		d.Dispatch(a)
		return len(d.Names())
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(strings.TrimSpace(n))] = true
	}
	channels := d.snapshot()

	sent := 0
	for _, c := range channels {
		if !want[strings.ToLower(c.Name())] {
			continue
		}
		sent++
		// An explicit DispatchTo (e.g. a scheduled report) is an intentional
		// send, so bypass any severity gate wrapping the channel — a low-severity
		// report must still reach an email channel gated to "critical" for alerts.
		target := c
		if g, ok := c.(interface{ Unguarded() Channel }); ok {
			target = g.Unguarded()
		}
		d.delivery.enqueue(sendJob{ch: target, alert: a})
	}
	return sent
}

// SendResult is the per-channel outcome of a DispatchToResults call.
type SendResult struct {
	Channel string
	Err     error
}

// DispatchToResults sends the alert to the named channels SYNCHRONOUSLY and
// returns a per-channel result, so a caller that needs delivery receipts (the
// report pipeline, recording per-channel DeliveryStatus) knows which channels
// succeeded. An empty/nil selection targets all channels. The intentional-send
// severity-gate bypass matches DispatchTo. Unlike Dispatch/DispatchTo, this
// blocks until every send returns — callers run it off the request path.
func (d *Dispatcher) DispatchToResults(a models.Alert, names []string) []SendResult {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(strings.TrimSpace(n))] = true
	}
	all := len(names) == 0

	channels := d.snapshot()

	var results []SendResult
	for _, c := range channels {
		if !all && !want[strings.ToLower(c.Name())] {
			continue
		}
		target := c
		if g, ok := c.(interface{ Unguarded() Channel }); ok {
			target = g.Unguarded()
		}
		results = append(results, SendResult{Channel: c.Name(), Err: target.Send(a)})
	}
	return results
}
