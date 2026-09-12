// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

import (
	"sort"
	"sync"
	"testing"
	"time"

	"netops/backend/models"
)

// stubChannel is a fake notify.Channel that records the alerts it receives, so
// dispatcher routing can be asserted without any real transport.
type stubChannel struct {
	name string
	mu   sync.Mutex
	got  []models.Alert
}

func (c *stubChannel) Name() string { return c.name }

func (c *stubChannel) Send(a models.Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, a)
	return nil
}

func (c *stubChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

// waitForSends polls until the channel has received `n` alerts or the deadline
// passes — Dispatch/DispatchTo fan out in goroutines, so delivery is async.
func waitForSends(t *testing.T, c *stubChannel, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.count() >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	if c.count() < n {
		t.Fatalf("channel %q received %d sends, want %d", c.name, c.count(), n)
	}
}

func dispatcherAlert() models.Alert {
	return models.Alert{ID: "a1", Rule: "test", Severity: "warning", Summary: "hi", FiredAt: time.Now()}
}

// Names lists every registered channel, in registration order; nil channels are
// ignored by Register and never appear.
func TestDispatcherNames(t *testing.T) {
	d := NewDispatcher()
	if got := d.Names(); len(got) != 0 {
		t.Fatalf("fresh dispatcher Names() = %v, want empty", got)
	}
	d.Register(&stubChannel{name: "slack"})
	d.Register(nil) // must be a no-op
	d.Register(&stubChannel{name: "email"})

	got := d.Names()
	want := []string{"slack", "email"}
	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// DispatchTo routes only to the named channels (case-insensitive), counting and
// delivering to just those — others stay untouched.
func TestDispatchToRoutesOnlyNamed(t *testing.T) {
	slack := &stubChannel{name: "slack"}
	email := &stubChannel{name: "email"}
	pd := &stubChannel{name: "pagerduty"}
	d := NewDispatcher()
	d.Register(slack)
	d.Register(email)
	d.Register(pd)

	// Mixed casing + whitespace must still match.
	sent := d.DispatchTo(dispatcherAlert(), []string{"Slack", "  PAGERDUTY  "})
	if sent != 2 {
		t.Fatalf("DispatchTo reported %d, want 2", sent)
	}
	waitForSends(t, slack, 1)
	waitForSends(t, pd, 1)

	// email was not named — give the goroutines time and assert it stayed empty.
	time.Sleep(20 * time.Millisecond)
	if email.count() != 0 {
		t.Errorf("email should not have received an alert, got %d", email.count())
	}
}

// DispatchTo with an unknown channel name routes to nobody and returns 0.
func TestDispatchToUnknownNameRoutesNowhere(t *testing.T) {
	slack := &stubChannel{name: "slack"}
	d := NewDispatcher()
	d.Register(slack)

	sent := d.DispatchTo(dispatcherAlert(), []string{"nonexistent"})
	if sent != 0 {
		t.Fatalf("DispatchTo(unknown) = %d, want 0", sent)
	}
	time.Sleep(20 * time.Millisecond)
	if slack.count() != 0 {
		t.Errorf("slack should not have received an alert, got %d", slack.count())
	}
}

// DispatchTo with an empty selection falls back to all channels and reports the
// total count.
func TestDispatchToEmptySelectionFansOutToAll(t *testing.T) {
	slack := &stubChannel{name: "slack"}
	email := &stubChannel{name: "email"}
	d := NewDispatcher()
	d.Register(slack)
	d.Register(email)

	sent := d.DispatchTo(dispatcherAlert(), nil)
	if sent != 2 {
		t.Fatalf("DispatchTo(nil) = %d, want 2", sent)
	}
	waitForSends(t, slack, 1)
	waitForSends(t, email, 1)
}

// Names() and DispatchTo() are consistent: DispatchTo to every Name() delivers
// to all of them.
func TestDispatchToAllNamedMatchesNames(t *testing.T) {
	d := NewDispatcher()
	chans := []*stubChannel{{name: "slack"}, {name: "email"}, {name: "sns"}}
	for _, c := range chans {
		d.Register(c)
	}
	names := d.Names()
	sort.Strings(names)
	sent := d.DispatchTo(dispatcherAlert(), names)
	if sent != len(chans) {
		t.Fatalf("DispatchTo(all names) = %d, want %d", sent, len(chans))
	}
	for _, c := range chans {
		waitForSends(t, c, 1)
	}
}
