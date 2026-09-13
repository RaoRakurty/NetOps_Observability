// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// if_registry_unread_test.go — tracker 307, the caller-side half.
//
// collectors.FetchIfAddrMap / FetchIfIndexMap / FetchRoutingDirection /
// FetchWANCircuits now REPORT a channel they could not read instead of answering
// "nothing is published there". Fixing the readers alone changes nothing
// observable, because every caller dropped the error on the floor
// (`ifaddr, _ :=`). The disposition the architect set for all of them is the
// same — the read only NAMES and ORIENTS, so it must not abort the caller's main
// job — which leaves exactly one obligation: the failure must be OBSERVABLE
// (CLAUDE.md §10). That is what these tests hold.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"netops/backend/collectors"
	"netops/backend/internal/applog"
	"netops/backend/models"
)

// capturedLog is one structured event the process logger emitted.
type capturedLog struct {
	level     string
	component string
	msg       string
	fields    map[string]any
}

// captureLogs installs the applog observer for the duration of one test and
// returns a reader for what was emitted. The observer runs on the emitting
// goroutine, so the mutex is not optional.
func captureLogs(t *testing.T) func() []capturedLog {
	t.Helper()
	var mu sync.Mutex
	var got []capturedLog
	restore := applog.SetObserver(func(level, component, msg string, fields map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, capturedLog{level: level, component: component, msg: msg, fields: fields})
	})
	t.Cleanup(restore)
	return func() []capturedLog {
		mu.Lock()
		defer mu.Unlock()
		out := make([]capturedLog, len(got))
		copy(out, got)
		return out
	}
}

func findLog(logs []capturedLog, component, substr string) (capturedLog, bool) {
	for _, l := range logs {
		if l.component == component && strings.Contains(l.msg, substr) {
			return l, true
		}
	}
	return capturedLog{}, false
}

// ---- the shared reporter -------------------------------------------------

// A channel that could not be read is a warning that names the consequence and
// carries the underlying error, every time. "Once per read" is the design: every
// caller is a ≥60s ticker or a single HTTP request, and a throttle that swallowed
// the FIRST line would hide the start of the outage.
func TestReportIfRegistryUnreadIsObservable(t *testing.T) {
	logs := captureLogs(t)
	reportIfRegistryUnread("topology", "port names are missing", fmt.Errorf("dial tcp: connection refused"),
		map[string]any{"devices": 3})
	got := logs()
	if len(got) != 1 {
		t.Fatalf("emitted %d event(s), want exactly 1 — an unread dependency must be neither silent nor repeated per call", len(got))
	}
	if got[0].level != "warn" {
		t.Errorf("level = %q, want warn", got[0].level)
	}
	if !strings.Contains(got[0].msg, "port names are missing") {
		t.Errorf("the line does not name the consequence: %q", got[0].msg)
	}
	if s, _ := got[0].fields["error"].(string); !strings.Contains(s, "connection refused") {
		t.Errorf("the line does not carry the underlying error: %#v", got[0].fields)
	}
	if got[0].fields["devices"] != 3 {
		t.Errorf("the caller's own context was dropped: %#v", got[0].fields)
	}
}

// A deployment that configures NO sharing channel runs no collector on the other
// end of it, so "nothing is published" is true of it. Warning on that would put
// a line in every enricher cycle of every single-node install, which is how a
// real §10 signal gets muted.
func TestReportIfRegistryUnreadStaysQuietWhenNoChannelIsConfigured(t *testing.T) {
	logs := captureLogs(t)
	reportIfRegistryUnread("topology", "port names are missing", collectors.ErrNotConfigured, nil)
	reportIfRegistryUnread("topology", "port names are missing", nil, nil)
	if got := logs(); len(got) != 0 {
		t.Fatalf("emitted %d event(s) for an unconfigured channel / a successful read, want 0: %+v", len(got), got)
	}
	if !errShareChannelUnread(errors.New("boom")) {
		t.Error("a plain read failure must count as unread")
	}
	if errShareChannelUnread(fmt.Errorf("wrapped: %w", collectors.ErrNotConfigured)) {
		t.Error("the not-configured sentinel must survive wrapping")
	}
}

// ---- the WAN projection, through its real DI seam -----------------------

// wanProject's interface registry is not merely a set of port labels: the
// in-scope interface set is derived from it, so an unread registry empties the
// WAN interface table and every circuit derived from it. The projection still
// ANSWERS — refusing the WAN page whenever the SNMP share channel blips costs
// more than the gap — but "this tenant has no WAN interfaces" must not be
// asserted silently.
func TestWanProjectReportsAnUnreadInterfaceRegistry(t *testing.T) {
	s := newWanTestServer(t, nil, nil)
	s.wanIfAddr = func(context.Context) (map[string]map[string]string, error) {
		return nil, fmt.Errorf("%w: read tcp: connection reset by peer", errors.New("redis: connection failed"))
	}
	s.discovery.Upsert(models.Device{ID: "wan-a", Name: "wan-a", Address: "10.0.0.254", TenantID: "acme"})

	logs := captureLogs(t)
	eps, circuits, err := s.wanProject(context.Background(), wanVis(s, "acme"))
	if err != nil {
		t.Fatalf("the projection was refused over a naming registry: %v — the disposition is degrade-and-report", err)
	}
	if len(eps) != 0 || len(circuits) != 0 {
		t.Fatalf("got %d endpoint(s)/%d circuit(s) from an unread registry", len(eps), len(circuits))
	}
	l, ok := findLog(logs(), "wan", "interface registry unread")
	if !ok {
		t.Fatalf("an unread interface registry produced an EMPTY WAN table and no log line — indistinguishable from a tenant with no WAN interfaces (§10): %+v", logs())
	}
	if !strings.Contains(l.msg, "EMPTY") {
		t.Errorf("the line does not say what the caller lost: %q", l.msg)
	}
	if l.fields["tenant"] != "acme" {
		t.Errorf("the line does not name the tenant whose table is empty: %#v", l.fields)
	}
}

// The same seam succeeding must stay silent, or the line becomes noise nobody
// reads and the guarantee above is worthless.
func TestWanProjectSaysNothingWhenTheRegistryReads(t *testing.T) {
	s := newWanTestServer(t, map[string]map[string]string{"wan-a": {"10.0.0.1": "Ethernet1"}}, nil)
	s.discovery.Upsert(models.Device{ID: "wan-a", Name: "wan-a", Address: "10.0.0.254", TenantID: "acme"})
	logs := captureLogs(t)
	if _, _, err := s.wanProject(context.Background(), wanVis(s, "acme")); err != nil {
		t.Fatalf("wanProject: %v", err)
	}
	if _, ok := findLog(logs(), "wan", "interface registry unread"); ok {
		t.Error("a successful registry read logged an unread warning")
	}
}
