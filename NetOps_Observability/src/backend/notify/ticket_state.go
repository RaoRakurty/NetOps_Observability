package notify

// ticket_state.go — the shared stateful core of the Jira and ServiceNow
// auto-ticketing connectors (#147 T4, lightening-audit finding 6). Both keep
// the same local state machine: an open-ticket dedup map keyed by alert
// fingerprint, a severity threshold, and durable persistence of the open set
// with F-62/F-78 write-failure accounting. Protocol code (create/resolve HTTP)
// stays per-connector; this core owns only local state.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ticketCore is embedded by both connectors; T is the connector's ticket type.
// The three accessors are set at construction because the ticket types are
// plain serialised structs (their JSON shape is a persisted contract).
type ticketCore[T any] struct {
	threshold     int    // minimum severity rank that cuts a ticket
	thresholdName string // human label for the threshold
	statePath     string

	mu   sync.Mutex
	open map[string]*T // fingerprint -> ticket
	// dedup-state persist observability (see noteStateWrite)
	stateWriteFailures atomic.Uint64
	lastStateErr       atomic.Value // string

	fingerprintOf func(*T) string
	isOpen        func(*T) bool
	openedAt      func(*T) time.Time
}

func newTicketCore[T any](fp func(*T) string, isOpen func(*T) bool, at func(*T) time.Time) ticketCore[T] {
	return ticketCore[T]{
		threshold:     severityRank("critical"),
		thresholdName: "critical",
		open:          make(map[string]*T),
		fingerprintOf: fp,
		isOpen:        isOpen,
		openedAt:      at,
	}
}

// setThreshold sets the minimum severity that cuts a ticket (default critical).
func (c *ticketCore[T]) setThreshold(sev string) {
	sev = strings.ToLower(strings.TrimSpace(sev))
	if sev == "" {
		return
	}
	c.threshold = severityRank(sev)
	c.thresholdName = sev
}

// ThresholdName is the minimum severity that cuts a ticket.
func (c *ticketCore[T]) ThresholdName() string { return c.thresholdName }

func (c *ticketCore[T]) meets(sev string) bool { return severityRank(sev) >= c.threshold }

// setStateFile makes open tickets durable across restarts.
func (c *ticketCore[T]) setStateFile(path string) {
	if path == "" {
		return
	}
	c.statePath = path
	c.loadState()
}

// tickets returns the currently-open tickets (newest first) for the status UI.
func (c *ticketCore[T]) tickets() []T {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]T, 0, len(c.open))
	for _, t := range c.open {
		if c.isOpen(t) {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, k int) bool { return c.openedAt(&out[i]).After(c.openedAt(&out[k])) })
	return out
}

// noteStateWrite records a dedup-state persist outcome. The remote ticket has
// already been created or closed by the time we get here, so a write failure
// must NOT fail the caller (that would re-file the ticket). It must also never
// be silent: a lost dedup map means a restart re-files one ticket per still-
// firing alert. Counted here and exported via StateWriteFailures for /metrics.
func (c *ticketCore[T]) noteStateWrite(err error) {
	if err != nil {
		c.stateWriteFailures.Add(1)
		c.lastStateErr.Store(err.Error())
	}
}

// StateWriteFailures reports how many open-ticket dedup writes have failed and
// the most recent reason ("" when none). Non-zero means duplicate tickets are
// possible across a restart.
func (c *ticketCore[T]) StateWriteFailures() (uint64, string) {
	n := c.stateWriteFailures.Load()
	msg, _ := c.lastStateErr.Load().(string)
	return n, msg
}

// saveLocked persists the open-ticket dedup map. It RETURNS its failure
// (F-62/F-78 class): this map is what stops a restart from re-filing a
// duplicate ticket for every still-firing alert, so a silent write failure is
// an outage that survives the outage. Caller holds the lock.
func (c *ticketCore[T]) saveLocked() error {
	if c.statePath == "" {
		return nil
	}
	list := make([]T, 0, len(c.open))
	for _, t := range c.open {
		if c.isOpen(t) {
			list = append(list, *t)
		}
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal open-ticket state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.statePath), 0o755); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write open-ticket state: %w", err)
	}
	if err := os.Rename(tmp, c.statePath); err != nil {
		return fmt.Errorf("commit open-ticket state: %w", err)
	}
	return nil
}

func (c *ticketCore[T]) loadState() {
	b, err := os.ReadFile(c.statePath)
	if err != nil {
		return
	}
	var list []T
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range list {
		t := list[i]
		c.open[c.fingerprintOf(&t)] = &t
	}
}
