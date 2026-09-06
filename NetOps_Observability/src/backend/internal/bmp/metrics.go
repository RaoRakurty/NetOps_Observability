// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// metrics.go — the module's Prometheus surface (§10: every service emits
// metrics, no silent failures).
//
// Every label value comes from a CLOSED vocabulary defined in this file or
// from MsgType.String(), which maps anything unassigned to "unknown". A router
// therefore cannot drive metric cardinality: no peer address, tenant id, device
// id or router-supplied string is ever used as a label.

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// Session outcomes (the `outcome` label on netops_bmp_sessions_total).
const (
	// OutcomeAccepted — the source resolved to a device and the session ran.
	OutcomeAccepted = "accepted"
	// OutcomeUnknownSource — the remote address matched no inventory device.
	// The connection is CLOSED: an unattributable feed is never admitted as
	// tenant "" (§3a).
	OutcomeUnknownSource = "unknown_source"
	// OutcomeAtCapacity — MaxConnections or MaxSessionRecords was reached.
	OutcomeAtCapacity = "at_capacity"
	// OutcomeBadAddress — the accepted connection had no usable remote IP.
	OutcomeBadAddress = "bad_address"
)

// Parse-error stages (the `stage` label on netops_bmp_parse_errors_total).
const (
	// StageHeader — the 6-byte common header was unreadable. The byte stream is
	// desynchronized and the session is dropped.
	StageHeader = "header"
	// StageMessage — the frame was read whole but its body did not parse. The
	// frame is skipped; the session continues.
	StageMessage = "message"
	// StageOversize — the peer declared a frame larger than MaxMessageSize.
	StageOversize = "oversize"
	// StageRead — the socket read failed or the deadline expired.
	StageRead = "read"
)

// Unsupported kinds (the `kind` label on netops_bmp_unsupported_total).
const (
	// KindMessageType — a well-framed BMP message of a type we do not decode.
	KindMessageType = "message_type"
	// KindAddressFamily — an MP_REACH/MP_UNREACH for an AFI/SAFI we do not
	// decode. Its routing information was NOT rendered.
	KindAddressFamily = "address_family"
	// KindPathAttribute — a path attribute type code we do not decode.
	KindPathAttribute = "path_attribute"
)

// Metrics holds the module's counters. The zero value is not usable; build it
// with NewMetrics. Every method is nil-safe so a metric-less deployment (or a
// test) needs no branching at the call sites.
type Metrics struct {
	mu           sync.Mutex
	sessions     map[string]uint64 // outcome → count
	active       int64
	messages     map[string]uint64 // message type → count
	parseErrors  map[string]uint64 // stage → count
	unsupported  map[string]uint64 // kind → count
	droppedUpdts uint64
	storedUpdts  uint64
}

// NewMetrics builds an empty counter set.
func NewMetrics() *Metrics {
	return &Metrics{
		sessions:    map[string]uint64{},
		messages:    map[string]uint64{},
		parseErrors: map[string]uint64{},
		unsupported: map[string]uint64{},
	}
}

func (m *Metrics) bump(bucket map[string]uint64, key string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket[key]++
}

// Session records one connection outcome.
func (m *Metrics) Session(outcome string) {
	if m == nil {
		return
	}
	m.bump(m.sessions, outcome)
}

// SessionOpened / SessionClosed track the live session gauge.
func (m *Metrics) SessionOpened() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.active++
	m.mu.Unlock()
}

// SessionClosed decrements the live session gauge. It floors at zero rather
// than going negative: a gauge that reads -1 is a bug reported as data.
func (m *Metrics) SessionClosed() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.active > 0 {
		m.active--
	}
	m.mu.Unlock()
}

// Message records one received BMP message by type.
func (m *Metrics) Message(t MsgType) {
	if m == nil {
		return
	}
	m.bump(m.messages, t.String())
}

// ParseError records one parse failure at the given stage.
func (m *Metrics) ParseError(stage string) {
	if m == nil {
		return
	}
	m.bump(m.parseErrors, stage)
}

// Unsupported records one deliberately-undecoded element.
func (m *Metrics) Unsupported(kind string, n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unsupported[kind] += uint64(n)
}

// UpdatesStored / UpdatesDropped record the ring's throughput and its
// backpressure. A non-zero dropped count is the honest signal that the stored
// feed is incomplete.
func (m *Metrics) UpdatesStored(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.storedUpdts += uint64(n)
	m.mu.Unlock()
}

// UpdatesDropped records updates evicted by the bounded ring.
func (m *Metrics) UpdatesDropped(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.droppedUpdts += uint64(n)
	m.mu.Unlock()
}

// Snapshot is a read-only copy of the counters, used by the /stats handler so
// the API reports the SAME numbers the scrape does.
type Snapshot struct {
	Sessions       map[string]uint64
	Active         int64
	Messages       map[string]uint64
	ParseErrors    map[string]uint64
	Unsupported    map[string]uint64
	UpdatesStored  uint64
	UpdatesDropped uint64
}

// Snapshot copies the counters under the lock.
func (m *Metrics) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{
			Sessions:    map[string]uint64{},
			Messages:    map[string]uint64{},
			ParseErrors: map[string]uint64{},
			Unsupported: map[string]uint64{},
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{
		Sessions:       copyCounts(m.sessions),
		Active:         m.active,
		Messages:       copyCounts(m.messages),
		ParseErrors:    copyCounts(m.parseErrors),
		Unsupported:    copyCounts(m.unsupported),
		UpdatesStored:  m.storedUpdts,
		UpdatesDropped: m.droppedUpdts,
	}
}

func copyCounts(src map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// Write emits the exposition text at scrape time. Label sets are written in
// sorted order so a scrape is byte-stable.
func (m *Metrics) Write(w io.Writer) {
	if m == nil {
		return
	}
	s := m.Snapshot()
	writeLabelled(w, "netops_bmp_sessions_total",
		"BMP connection outcomes: accepted, or refused because the source resolved to no device / the receiver was at capacity.",
		"outcome", s.Sessions)

	fmt.Fprintf(w, "# HELP netops_bmp_sessions_active BMP sessions currently connected.\n")
	fmt.Fprintf(w, "# TYPE netops_bmp_sessions_active gauge\n")
	fmt.Fprintf(w, "netops_bmp_sessions_active %d\n", s.Active)

	writeLabelled(w, "netops_bmp_messages_total",
		"BMP messages received, by RFC 7854 message type.",
		"type", s.Messages)
	writeLabelled(w, "netops_bmp_parse_errors_total",
		"BMP frames that could not be parsed, by stage. A header error drops the session; a message error skips one frame.",
		"stage", s.ParseErrors)
	writeLabelled(w, "netops_bmp_unsupported_total",
		"Well-formed elements this receiver deliberately does not decode, by kind. Non-zero means routing information arrived that is NOT reflected in the feed.",
		"kind", s.Unsupported)

	fmt.Fprintf(w, "# HELP netops_bmp_updates_stored_total Per-prefix update records added to the bounded per-session ring.\n")
	fmt.Fprintf(w, "# TYPE netops_bmp_updates_stored_total counter\n")
	fmt.Fprintf(w, "netops_bmp_updates_stored_total %d\n", s.UpdatesStored)

	fmt.Fprintf(w, "# HELP netops_bmp_updates_dropped_total Update records evicted by the bounded ring (drop-oldest backpressure). Non-zero means the stored feed is incomplete.\n")
	fmt.Fprintf(w, "# TYPE netops_bmp_updates_dropped_total counter\n")
	fmt.Fprintf(w, "netops_bmp_updates_dropped_total %d\n", s.UpdatesDropped)
}

// writeLabelled emits one counter family with a single label, sorted.
func writeLabelled(w io.Writer, name, help, label string, vals map[string]uint64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	if len(vals) == 0 {
		return
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, vals[k])
	}
}
