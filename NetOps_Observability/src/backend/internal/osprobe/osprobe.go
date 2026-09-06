// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package osprobe is the OS-VERSION SOURCE LADDER: the one place that answers
// "what software is this device running?" using every transport the platform
// already has credentials for, in a fixed order, recording WHICH one answered.
//
// THE PROBLEM IT KILLS. Advisory assessment needs a version or it must report a
// device UNASSESSED — never "not vulnerable" (§5g). Until now the only version
// source was the SNMP sysDescr, so a device that answers no SNMP could never be
// assessed however reachable it was by other means. The reference lab is the
// worked example: its two Nokia SR Linux spines are hand-authored rows carrying
// os="SR Linux" and no version, containerlab's SR Linux runs no SNMP agent
// unless one is configured (an snmpget from the collector host times out), and
// so /api/vulns reported `{device_id: spine1, reason: "OS version not present in
// sysDescr or os_version"}` against a 119,838-advisory feed — forever, while the
// same box answered `show version` over SSH and served a software-version leaf
// over gNMI.
//
// THE LADDER. First answer wins, and the answer carries its provenance:
//
//	(a) snmp — the sysDescr, the existing source, still the top rung because it
//	    is the device's own description and the only one that needs no
//	    per-platform knowledge at all;
//	(b) gnmi — the platform's software-version leaf, at the paths its vendor
//	    profile declares (SR Linux /platform/control[slot=A]/software-version,
//	    OpenConfig /system/state/software-version);
//	(c) ssh  — the profile's own capture.show_version_cmd through the read-only
//	    SSH gateway, parsed by the per-platform regexp in the profile.
//
// WHAT THIS PACKAGE WILL NOT DO. It never prompts, never writes to a device,
// never runs a command that is not the string the vendor profile returned, and
// never invents a version: a rung that answers with nothing is a rung that
// answered with nothing, reported as such and counted, and the device stays
// honestly unassessed. Every transport is INJECTED (§2/§5), so a deployment that
// has not wired one simply has that rung report itself unavailable instead of
// the ladder pretending a capability it does not have.
//
// WHERE THE VENDOR KNOWLEDGE LIVES. Not here. The gNMI paths, the CLI command
// and the two extraction patterns are DECLARATIVE DATA in
// internal/vendorprofile (`os_version_probe`), resolved through the registry —
// the ONE VOCABULARY rule (§13, vendorprofile/vocabulary_guard_test.go). This
// package holds the ORDER, the overwrite rule and the metrics, and nothing that
// names a vendor.
package osprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// Method is the transport a version reading came from. It is also the value
// stamped on the device row's os_version_source, so the strings are part of the
// API contract, not internal labels.
type Method string

const (
	// MethodSNMP is the sysDescr rung.
	MethodSNMP Method = "snmp"
	// MethodGNMI is the software-version leaf rung.
	MethodGNMI Method = "gnmi"
	// MethodSSH is the read-only `show version` rung.
	MethodSSH Method = "ssh"
	// MethodManual is NOT a rung: it is the provenance of a value an operator,
	// an inventory file or an importer wrote. It exists here because the
	// overwrite rule has to be able to name it.
	MethodManual Method = "manual"
)

// LadderOrder is the fixed rung order, top first. Exported because the order IS
// the design decision, and a test pins it.
var LadderOrder = []Method{MethodSNMP, MethodGNMI, MethodSSH}

// MaxOSVersionBytes bounds one reading (§9: bound everything). The value is
// written to an inventory row and displayed in a table; a device that answers
// with a megabyte is answering with garbage, and the reading is truncated rather
// than stored whole.
const MaxOSVersionBytes = 200

// Outcome is the per-probe result recorded on the metric.
const (
	// OutcomeLearned — the rung produced a version.
	OutcomeLearned = "learned"
	// OutcomeNoVersion — the transport answered, but nothing in the answer was
	// a version this platform's profile could read. Not an error, and NOT a
	// reason to write anything.
	OutcomeNoVersion = "no_version"
	// OutcomeUnavailable — the rung is not usable for this device: no transport
	// injected, no profile data, no address, no credential.
	OutcomeUnavailable = "unavailable"
	// OutcomeError — the probe failed (dial, auth, timeout, refused).
	OutcomeError = "error"
)

// ErrNotConfigured is the honest "this rung cannot run for this device". It is
// distinct from a probe FAILURE on purpose: a rung that was never wired has not
// observed anything about the device, and conflating the two would let a
// missing capability read as a device problem (§10, and the silent-failure
// guard's own rule).
var ErrNotConfigured = errors.New("osprobe: source not configured for this device")

// Target is the read-only view of a device a rung may use. It carries no
// credentials: each transport resolves its own through its own injected
// custody, so this struct can be logged.
type Target struct {
	DeviceID string
	Name     string
	Address  string
	Vendor   string
	// OSText is the row's free-form OS/platform label ("SR Linux", "Cisco
	// IOS-XE 17.9", a whole sysDescr). It is what resolves the vendor profile.
	OSText string
	// TenantID is the owning tenant of the inventory row. The ladder never
	// crosses it: it probes the device the row names and writes back to that
	// same row, so the tenant travels with the work rather than being
	// re-derived anywhere downstream (§3a).
	TenantID string
}

// Reading is one rung's answer, already rendered into the canonical form the
// vendor's own os_version_pattern parses.
type Reading struct {
	Version string
	Method  Method
	At      time.Time
}

// Current is what the device row already holds. Source "" means a value of
// UNKNOWN provenance — a row written by an operator, an inventory file or an
// importer before this field existed — and is treated exactly like MethodManual.
type Current struct {
	Version string
	Source  Method
	At      time.Time
}

// automatic reports whether m is a rung this package can re-run. Manual (and
// unknown) provenance is not: nothing here can reproduce what a person typed.
func (m Method) automatic() bool {
	for _, k := range LadderOrder {
		if k == m {
			return true
		}
	}
	return false
}

// Accept is the OVERWRITE RULE, and it is deliberately conservative.
//
//  1. An EMPTY reading is NEVER written. A probe that answered with nothing
//     cannot erase what an operator wrote or an earlier probe learned — a
//     transient SNMP timeout must not blank a device's version and drop it back
//     to unassessed.
//  2. A row whose value came from the SAME method is always refreshed by a
//     newer read of that method. The device is authoritative about its own
//     software, and this is the path that keeps a row current across an upgrade.
//  3. A reading from a DIFFERENT method replaces the row's value ONLY when that
//     value is EMPTY. The ladder order already decided which method SHOULD
//     answer for this device, so a lower rung that happens to run later must
//     not fight a higher rung for the row; and a value an operator wrote
//     (source "manual", or "" for a row written before the field existed) is
//     never displaced by a probe at all.
//
// KNOWN RESIDUAL, stated rather than hidden: rule 3 means a version first
// learned over SSH is not later replaced by an SNMP reading, so a device that
// is upgraded AFTER its SSH rung stops working keeps a stale (but real, once
// read off the device) version until the SSH rung answers again. The
// alternative — letting a higher rung win — lets one flapping transport
// repeatedly rewrite the row, which is the worse failure for an advisory
// assessment that has to be stable enough to act on.
func Accept(cur Current, r Reading) bool {
	if strings.TrimSpace(r.Version) == "" {
		return false // rule 1
	}
	if !r.Method.automatic() {
		return false // only a rung may write through this path
	}
	if strings.TrimSpace(cur.Version) == "" {
		return true // rule 3, the empty case
	}
	return cur.Source == r.Method // rule 2
}

// Plan returns the rungs whose reading could possibly be ACCEPTED onto a row
// that currently holds cur, in ladder order. It is derived from Accept, and the
// derivation is the point: the ladder must never run a transport at a live
// device only to throw the answer away. A row holding an operator's value plans
// NO probes at all.
func Plan(cur Current) []Method {
	if strings.TrimSpace(cur.Version) == "" {
		return append([]Method(nil), LadderOrder...)
	}
	if cur.Source.automatic() {
		return []Method{cur.Source}
	}
	return nil
}

// Source is ONE rung. Probe returns the version ALREADY RENDERED into the
// canonical form the vendor's os_version_pattern parses; ("", nil) is the
// honest "the transport answered and carried no version", and
// ("", ErrNotConfigured) is "this rung cannot run here".
type Source interface {
	Method() Method
	Probe(ctx context.Context, t Target) (string, error)
}

// Ladder runs the rungs in order and records what happened. It holds no
// ambient authority: every transport arrived through a constructor argument.
type Ladder struct {
	sources []Source
	metrics *metrics
	// logf is the structured-log sink. Nil falls back to the stdlib logger —
	// never to silence: a probe failure the operator cannot see is exactly the
	// silent failure §10 forbids.
	logf func(msg string, fields map[string]any)
	now  func() time.Time
	// timeout bounds ONE rung against ONE device (§9).
	timeout time.Duration
}

// DefaultProbeTimeout bounds one rung against one device. A `show version` that
// has not answered inside it is a failed probe, not a reason to hold up the
// enrichment tick for the rest of the fleet.
const DefaultProbeTimeout = 20 * time.Second

// NewLadder builds a ladder from the rungs a deployment actually wired. Sources
// are re-ordered into LadderOrder, so a caller cannot accidentally invert the
// design's precedence by passing them in the wrong order; a source whose method
// is not a rung is refused.
func NewLadder(logf func(msg string, fields map[string]any), sources ...Source) (*Ladder, error) {
	byMethod := map[Method]Source{}
	for _, s := range sources {
		if s == nil {
			continue
		}
		if !s.Method().automatic() {
			return nil, fmt.Errorf("osprobe: %q is not a ladder rung", s.Method())
		}
		if _, dup := byMethod[s.Method()]; dup {
			return nil, fmt.Errorf("osprobe: two sources declare method %q", s.Method())
		}
		byMethod[s.Method()] = s
	}
	l := &Ladder{
		metrics: newMetrics(),
		logf:    logf,
		now:     time.Now,
		timeout: DefaultProbeTimeout,
	}
	for _, m := range LadderOrder {
		if s, ok := byMethod[m]; ok {
			l.sources = append(l.sources, s)
		}
	}
	return l, nil
}

// SetTimeout overrides the per-rung bound (tests, and a deployment whose
// devices are genuinely slower). A non-positive value is ignored rather than
// removing the bound.
func (l *Ladder) SetTimeout(d time.Duration) {
	if d > 0 {
		l.timeout = d
	}
}

// Probe runs the rungs Plan allows for cur, top first, and returns the first
// reading that Accept would take. ok=false means no rung produced an acceptable
// version — the caller writes NOTHING and the device stays honestly unassessed.
func (l *Ladder) Probe(ctx context.Context, t Target, cur Current) (Reading, bool) {
	allowed := map[Method]bool{}
	for _, m := range Plan(cur) {
		allowed[m] = true
	}
	if len(allowed) == 0 {
		return Reading{}, false
	}
	for _, src := range l.sources {
		if !allowed[src.Method()] {
			continue
		}
		version, err := l.runOne(ctx, src, t)
		if err != nil {
			continue
		}
		if version == "" {
			continue
		}
		r := Reading{Version: version, Method: src.Method(), At: l.now().UTC()}
		if !Accept(cur, r) {
			// Plan is derived from Accept, so this is unreachable unless the two
			// drift apart — which is a defect worth SEEING rather than a branch
			// worth swallowing (§10).
			l.log("os-version probe produced a reading its own plan would refuse", map[string]any{
				"device_id": t.DeviceID, "method": string(src.Method()),
				"current_source": string(cur.Source),
			})
			continue
		}
		return r, true
	}
	return Reading{}, false
}

// runOne bounds and observes one rung. It returns ("", err) on failure and
// ("", nil) when the transport answered without a version; both are counted and
// the failure is logged.
func (l *Ladder) runOne(ctx context.Context, src Source, t Target) (string, error) {
	pctx, cancel := context.WithTimeout(ctx, l.timeout)
	defer cancel()
	version, err := src.Probe(pctx, t)
	method := string(src.Method())
	switch {
	case errors.Is(err, ErrNotConfigured):
		l.metrics.inc(method, OutcomeUnavailable)
		return "", err
	case err != nil:
		l.metrics.inc(method, OutcomeError)
		l.log("os-version probe failed", map[string]any{
			"device_id": t.DeviceID, "tenant": t.TenantID, "method": method,
			"vendor": t.Vendor, "error": err.Error(),
		})
		return "", err
	}
	version = boundVersion(version)
	if version == "" {
		l.metrics.inc(method, OutcomeNoVersion)
		l.log("os-version probe answered with no version", map[string]any{
			"device_id": t.DeviceID, "tenant": t.TenantID, "method": method,
			"vendor": t.Vendor,
		})
		return "", nil
	}
	l.metrics.inc(method, OutcomeLearned)
	return version, nil
}

// boundVersion trims and caps a reading (§9). It is the ONE place the cap is
// applied, so no rung can store more than the row is meant to hold.
func boundVersion(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > MaxOSVersionBytes {
		s = strings.TrimSpace(s[:MaxOSVersionBytes])
	}
	return s
}

func (l *Ladder) log(msg string, fields map[string]any) {
	if l.logf != nil {
		l.logf(msg, fields)
		return
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("osprobe: ")
	b.WriteString(msg)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%v", k, fields[k])
	}
	log.Print(b.String())
}

// WriteMetrics emits the ladder's counter in Prometheus exposition format
// (§10). Nil-safe so a deployment that wired no ladder still scrapes.
func (l *Ladder) WriteMetrics(w io.Writer) {
	if l == nil {
		return
	}
	l.metrics.write(w)
}

// metrics is the ladder's own counter. It is a struct field, not a package
// global (§5) — two ladders in one process (a test and the server) count
// separately, which is what makes the counter testable at all.
type metrics struct {
	mu     sync.Mutex
	counts map[string]uint64
}

func newMetrics() *metrics { return &metrics{counts: map[string]uint64{}} }

func (m *metrics) inc(method, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counts[method+"\x00"+outcome]++
}

// snapshot returns the counter as a sorted, label-decoded list.
func (m *metrics) snapshot() [][3]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.counts))
	for k := range m.counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][3]string, 0, len(keys))
	for _, k := range keys {
		method, outcome, _ := strings.Cut(k, "\x00")
		out = append(out, [3]string{method, outcome, fmt.Sprint(m.counts[k])})
	}
	return out
}

func (m *metrics) write(w io.Writer) {
	rows := m.snapshot()
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP netops_device_osversion_probe_total OS-version probes by ladder rung and outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_device_osversion_probe_total counter\n")
	for _, r := range rows {
		fmt.Fprintf(w, "netops_device_osversion_probe_total{method=%q,outcome=%q} %s\n", r[0], r[1], r[2])
	}
}
