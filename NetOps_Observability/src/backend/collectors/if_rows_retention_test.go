// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

// if_rows_retention_test.go — a device that stops answering polls keeps its
// last-known interface rows, inside the bounds that stop a row outliving the
// device, its tenant or its address.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/applog"
)

var ifRowsT0 = time.Date(2026, 11, 7, 4, 55, 0, 0, time.UTC)

// answered is a poll that completed both walks.
func answered(id, tenant string, addrs ...string) ifRowInput {
	addr := map[string]string{}
	for _, a := range addrs {
		addr[a] = "if-" + a
	}
	return ifRowInput{
		id: id, tenant: tenant,
		addr: addr, addrComplete: true,
		index: map[string]string{"1": "Gi1"}, indexComplete: true,
	}
}

// silent is a poll the device did not answer.
func silent(id, tenant string) ifRowInput { return ifRowInput{id: id, tenant: tenant} }

func addrsOf(cy ifRowCycle, id string) []string {
	out := make([]string, 0, len(cy.addr[id]))
	for ip := range cy.addr[id] {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func wantAddrs(t *testing.T, cy ifRowCycle, id string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := addrsOf(cy, id); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s addresses = %v, want %v", id, got, want)
	}
}

func applyAt(st *ifRowState, at time.Time, inputs ...ifRowInput) ifRowCycle {
	return st.apply(at, inputs, ifRowMaxAge, ifRowAbsentGrace)
}

func TestIfRowsDeviceThatFailsAPollKeepsItsRows(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "192.168.200.33", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Hour), silent("a", "t1"))

	wantAddrs(t, cy, "a", "10.0.0.1", "192.168.200.33")
	if cy.index["a"]["1"] != "Gi1" {
		t.Fatalf("ifIndex rows not retained: %v", cy.index)
	}
	if !reflect.DeepEqual(cy.retained, []string{"a"}) || cy.oldestAge != time.Hour {
		t.Fatalf("retained=%v oldest=%v, want [a] 1h", cy.retained, cy.oldestAge)
	}
}

func TestIfRowsDeviceThatAnswersReplacesItsRowsInFull(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1", "10.0.0.2"))
	applyAt(&st, ifRowsT0.Add(time.Minute), silent("a", "t1"))

	cy := applyAt(&st, ifRowsT0.Add(2*time.Minute), answered("a", "t1", "10.0.0.2"))

	wantAddrs(t, cy, "a", "10.0.0.2")
	if len(cy.retained) != 0 || cy.oldestAge != 0 {
		t.Fatalf("an answering device is not retained: %v %v", cy.retained, cy.oldestAge)
	}
	// And it stays gone when the device then falls silent.
	cy = applyAt(&st, ifRowsT0.Add(3*time.Minute), silent("a", "t1"))
	wantAddrs(t, cy, "a", "10.0.0.2")
}

// A completed walk that reports nothing is an answer: every address is gone.
func TestIfRowsCompleteEmptyAnswerRemovesEverything(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))
	empty := answered("a", "t1")
	empty.index, empty.addr = nil, nil

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), empty)

	wantAddrs(t, cy, "a")
	if _, ok := st.Devices["a"]; ok {
		t.Fatal("a device with no rows must not hold state")
	}
}

// An incomplete read adds what it saw and removes nothing: the walk was cut off, so
// a missing row says nothing about the device.
func TestIfRowsIncompleteReadCannotRemoveARow(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1", "10.0.0.2"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), ifRowInput{
		id: "a", tenant: "t1", addr: map[string]string{"10.0.0.3": "Gi3"},
	})

	wantAddrs(t, cy, "a", "10.0.0.1", "10.0.0.2", "10.0.0.3")
	if !reflect.DeepEqual(cy.retained, []string{"a"}) {
		t.Fatalf("a partial read is not a confirmed answer: retained=%v", cy.retained)
	}
	if st.Devices["a"].Addr.At != ifRowsT0.UnixMilli() {
		t.Fatal("a partial read must not refresh the age bound")
	}
}

func TestIfRowsAgeOutAtTheBound(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(ifRowMaxAge-time.Minute), silent("a", "t1"))
	wantAddrs(t, cy, "a", "10.0.0.1")

	cy = applyAt(&st, ifRowsT0.Add(ifRowMaxAge), silent("a", "t1"))
	wantAddrs(t, cy, "a")
	if len(cy.index["a"]) != 0 || cy.expired != 1 || len(cy.retained) != 0 {
		t.Fatalf("past the bound nothing is served: %+v", cy)
	}
	if _, ok := st.Devices["a"]; ok {
		t.Fatal("an expired device must leave the state")
	}
}

// The two maps age apart: a device whose address walk keeps failing while its name
// table answers is not kept alive by the name table.
func TestIfRowsMapsAgeIndependently(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(ifRowMaxAge), ifRowInput{
		id: "a", tenant: "t1", index: map[string]string{"1": "Gi1"}, indexComplete: true,
	})

	wantAddrs(t, cy, "a")
	if cy.index["a"]["1"] != "Gi1" {
		t.Fatalf("index rows were just confirmed: %v", cy.index)
	}
}

func TestIfRowsRemovedFromInventoryStopsBeingPublishedAtOnce(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"), answered("b", "t1", "10.0.0.2"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), silent("b", "t1"))
	wantAddrs(t, cy, "a")
	wantAddrs(t, cy, "b", "10.0.0.2")

	// The state keeps it only for the grace, and then only until then.
	if _, ok := st.Devices["a"]; !ok {
		t.Fatal("inside the grace the state keeps a device (boot-time gap)")
	}
	cy = applyAt(&st, ifRowsT0.Add(time.Minute+ifRowAbsentGrace), silent("b", "t1"))
	if _, ok := st.Devices["a"]; ok || cy.absent != 1 {
		t.Fatalf("past the grace a removed device leaves the state: absent=%d", cy.absent)
	}
}

// The boot gap: the first poll after a restart runs before NetBox has answered. A
// device missing for a moment comes back with its rows.
func TestIfRowsBriefAbsenceDoesNotLoseRows(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute))
	wantAddrs(t, cy, "a")

	cy = applyAt(&st, ifRowsT0.Add(2*time.Minute), silent("a", "t1"))
	wantAddrs(t, cy, "a", "10.0.0.1")
	if st.Devices["a"].AbsentSince != 0 {
		t.Fatal("a returning device is present again")
	}
}

func TestIfRowsMovedAddressFreshAnswerWins(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1", "10.0.0.9"), answered("b", "t1", "10.0.0.2"))

	// a falls silent; later b gains the address.
	applyAt(&st, ifRowsT0.Add(time.Minute), silent("a", "t1"), answered("b", "t1", "10.0.0.2"))
	cy := applyAt(&st, ifRowsT0.Add(2*time.Minute), silent("a", "t1"), answered("b", "t1", "10.0.0.2", "10.0.0.1"))

	wantAddrs(t, cy, "a", "10.0.0.9")
	wantAddrs(t, cy, "b", "10.0.0.1", "10.0.0.2")
	if cy.moved != 1 {
		t.Fatalf("moved=%d, want 1", cy.moved)
	}
	// a comes back still claiming it: now both are fresh, and that IS a conflict.
	cy = applyAt(&st, ifRowsT0.Add(3*time.Minute), answered("a", "t1", "10.0.0.1"), answered("b", "t1", "10.0.0.2", "10.0.0.1"))
	wantAddrs(t, cy, "a", "10.0.0.1")
	wantAddrs(t, cy, "b", "10.0.0.1", "10.0.0.2")
}

// Two devices claiming one address at the same time: dropping the silent one's row
// would resolve the address to the survivor, the guess the resolver exists to refuse.
func TestIfRowsSharedAddressStaysClaimedByBoth(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "192.168.1.1"), answered("b", "t1", "192.168.1.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Hour), silent("a", "t1"), answered("b", "t1", "192.168.1.1"))

	wantAddrs(t, cy, "a", "192.168.1.1")
	wantAddrs(t, cy, "b", "192.168.1.1")
	if cy.moved != 0 {
		t.Fatalf("a shared address did not move: moved=%d", cy.moved)
	}
	// Both silent: still both.
	cy = applyAt(&st, ifRowsT0.Add(2*time.Hour), silent("a", "t1"), silent("b", "t1"))
	wantAddrs(t, cy, "a", "192.168.1.1")
	wantAddrs(t, cy, "b", "192.168.1.1")
}

// §3a: one tenant's poll must not edit another tenant's rows, however its address
// compares. Overlapping private space across tenants is the normal case.
func TestIfRowsOtherTenantsAnswerNeverEvicts(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))
	applyAt(&st, ifRowsT0.Add(time.Minute), silent("a", "t1"), answered("b", "t2", "10.0.0.2"))

	cy := applyAt(&st, ifRowsT0.Add(2*time.Minute), silent("a", "t1"), answered("b", "t2", "10.0.0.1"))

	wantAddrs(t, cy, "a", "10.0.0.1")
	wantAddrs(t, cy, "b", "10.0.0.1")
	if cy.moved != 0 {
		t.Fatalf("a claim crossed tenants: moved=%d", cy.moved)
	}
}

// §3a: retained rows never reach a device's new owner.
func TestIfRowsTenantChangeDiscardsRetainedRows(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), silent("a", "t2"))

	wantAddrs(t, cy, "a")
	if len(cy.index["a"]) != 0 || cy.tenantChanged != 1 {
		t.Fatalf("rows outlived a tenant change: %+v", cy)
	}
	// Moving back must not resurrect them: they were discarded, not hidden.
	cy = applyAt(&st, ifRowsT0.Add(2*time.Minute), silent("a", "t1"))
	wantAddrs(t, cy, "a")
}

func TestIfRowsTenantChangeWithAnAnswerKeepsOnlyTheFreshRows(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), ifRowInput{id: "a", tenant: "t2", addr: map[string]string{"10.0.0.2": "Gi2"}})

	wantAddrs(t, cy, "a", "10.0.0.2")
	if st.Devices["a"].Tenant != "t2" {
		t.Fatalf("entry tenant = %q", st.Devices["a"].Tenant)
	}
}

// A tenant change during an absence: the device comes back under another owner.
func TestIfRowsTenantChangeDuringAbsenceDiscards(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))
	applyAt(&st, ifRowsT0.Add(time.Minute))

	cy := applyAt(&st, ifRowsT0.Add(2*time.Minute), silent("a", "t2"))
	wantAddrs(t, cy, "a")
}

// Spelling is not a tenant change; the exporter normalises the same way.
func TestIfRowsTenantSpellingIsNotAChange(t *testing.T) {
	st := newIfRowState()
	applyAt(&st, ifRowsT0, answered("a", " Acme ", "10.0.0.1"))

	cy := applyAt(&st, ifRowsT0.Add(time.Minute), silent("a", "acme"))
	wantAddrs(t, cy, "a", "10.0.0.1")
}

func TestIfRowsStateIsBoundedByTheTargetSet(t *testing.T) {
	st := newIfRowState()
	for i := 0; i < 50; i++ {
		id := fmt.Sprintf("d%d", i)
		applyAt(&st, ifRowsT0.Add(time.Duration(i)*time.Minute), answered(id, "t1", "10.0.0.1"))
	}
	applyAt(&st, ifRowsT0.Add(50*time.Minute+ifRowAbsentGrace))
	applyAt(&st, ifRowsT0.Add(50*time.Minute+2*ifRowAbsentGrace))
	if len(st.Devices) != 0 {
		t.Fatalf("state holds %d devices outside the target set", len(st.Devices))
	}
}

func TestIfRowsSanitizeRefusesWhatCannotBeAged(t *testing.T) {
	st := newIfRowState()
	st.Devices["future"] = &ifRowEntry{Addr: ifRowSet{Rows: map[string]string{"10.0.0.1": "x"}, At: ifRowsT0.Add(time.Hour).UnixMilli()}}
	st.Devices["unstamped"] = &ifRowEntry{Addr: ifRowSet{Rows: map[string]string{"10.0.0.2": "x"}}}
	st.Devices["nil"] = nil
	st.Devices[""] = &ifRowEntry{Addr: ifRowSet{Rows: map[string]string{"10.0.0.3": "x"}, At: ifRowsT0.UnixMilli()}}
	st.Devices["good"] = &ifRowEntry{Addr: ifRowSet{Rows: map[string]string{"10.0.0.4": "x"}, At: ifRowsT0.UnixMilli()}}

	st.sanitize(ifRowsT0)

	if len(st.Devices) != 1 || st.Devices["good"] == nil {
		t.Fatalf("after sanitize: %v", st.Devices)
	}
	if st.Devices["good"].AddrFirst["10.0.0.4"] != ifRowsT0.UnixMilli() {
		t.Fatal("a row without a claim stamp is stamped on load")
	}
}

// ---- through pollOnce and a real channel -----------------------------------

// fakeValkey speaks enough RESP for GET and SET … EX, across reconnects.
type fakeValkey struct {
	mu   sync.Mutex
	vals map[string]string
	ttls map[string]int
	sets map[string]int
}

func newFakeValkey(t *testing.T) *fakeValkey {
	t.Helper()
	fv := &fakeValkey{vals: map[string]string{}, ttls: map[string]int{}, sets: map[string]int{}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	t.Setenv("REDIS_HOST", host)
	t.Setenv("REDIS_PORT", port)
	t.Setenv("REDIS_PASSWORD", "")
	t.Setenv("REDIS_TLS", "")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go fv.serve(c)
		}
	}()
	return fv
}

func (fv *fakeValkey) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		hdr, err := r.ReadString('\n')
		if err != nil || len(hdr) == 0 || hdr[0] != '*' {
			return
		}
		n, err := strconv.Atoi(strings.TrimSpace(hdr[1:]))
		if err != nil {
			return
		}
		args := make([]string, n)
		for i := range args {
			l, err := r.ReadString('\n')
			if err != nil {
				return
			}
			size, err := strconv.Atoi(strings.TrimSpace(l[1:]))
			if err != nil {
				return
			}
			buf := make([]byte, size+2)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			args[i] = string(buf[:size])
		}
		fv.mu.Lock()
		reply := "+OK\r\n"
		switch strings.ToUpper(args[0]) {
		case "GET":
			if v, ok := fv.vals[args[1]]; ok {
				reply = fmt.Sprintf("$%d\r\n%s\r\n", len(v), v)
			} else {
				reply = "$-1\r\n"
			}
		case "SET":
			fv.vals[args[1]] = args[2]
			fv.sets[args[1]]++
			if len(args) >= 5 {
				ttl, err := strconv.Atoi(args[4])
				if err == nil {
					fv.ttls[args[1]] = ttl
				}
			}
		}
		fv.mu.Unlock()
		if _, err := c.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (fv *fakeValkey) expire(key string) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	delete(fv.vals, key)
}

func (fv *fakeValkey) ttl(key string) int {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return fv.ttls[key]
}

func (fv *fakeValkey) put(key, val string) {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	fv.vals[key] = val
}

func (fv *fakeValkey) setCount(key string) int {
	fv.mu.Lock()
	defer fv.mu.Unlock()
	return fv.sets[key]
}

// newRowsCollector builds a collector whose polls are scripted per device. A device
// missing from the script does not answer.
func newRowsCollector(targets *[]Target, script map[string]deviceOutcome) *metricsCollector {
	c := NewSNMPMetrics(func() []Target { return *targets }).(*metricsCollector)
	c.profiles = nil
	c.pollFn = func(_ context.Context, tg Target) deviceOutcome {
		if r, ok := script[tg.ID]; ok {
			r.id = tg.ID
			r.reach = true
			return r
		}
		return deviceOutcome{lastErr: "snmp: timeout"}
	}
	return c
}

func answeredOutcome(addrs ...string) deviceOutcome {
	m := map[string]string{}
	for _, a := range addrs {
		m[a] = "if-" + a
	}
	return deviceOutcome{ifaddr: m, ifaddrComplete: true, ifindex: map[string]string{"1": "Gi1"}, ifindexComplete: true}
}

func TestIfRowsSurviveACollectorRestart(t *testing.T) {
	fv := newFakeValkey(t)
	ctx := context.Background()
	targets := []Target{{ID: "cedge-81", TenantID: "t1", Address: "192.0.2.81"}}

	first := newRowsCollector(&targets, map[string]deviceOutcome{"cedge-81": answeredOutcome("192.168.200.33")})
	first.pollOnce(ctx)

	// The api restarts during the outage, for longer than the published maps' TTL.
	fv.expire(ifAddrKey)
	fv.expire(ifIndexKey)
	second := newRowsCollector(&targets, map[string]deviceOutcome{})
	second.pollOnce(ctx)

	m, err := FetchIfAddrMap(ctx)
	if err != nil {
		t.Fatalf("FetchIfAddrMap: %v", err)
	}
	if m["cedge-81"]["192.168.200.33"] != "if-192.168.200.33" {
		t.Fatalf("restart lost the retained row: %v", m)
	}
	idx, err := FetchIfIndexMap(ctx)
	if err != nil {
		t.Fatalf("FetchIfIndexMap: %v", err)
	}
	if idx["cedge-81"]["1"] != "Gi1" {
		t.Fatalf("restart lost the ifIndex row: %v", idx)
	}
}

// The state key outlives the bound; the published maps still self-expire if the
// collector dies, so a stopped collector cannot leave rows up for a week.
func TestIfRowsKeyTTLs(t *testing.T) {
	fv := newFakeValkey(t)
	targets := []Target{{ID: "a", Address: "192.0.2.1"}}
	newRowsCollector(&targets, map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")}).pollOnce(context.Background())

	if got := fv.ttl(ifAddrKey); got != 1800 {
		t.Fatalf("ifaddr TTL=%d", got)
	}
	if got := fv.ttl(ifIndexKey); got != 1800 {
		t.Fatalf("ifindex TTL=%d", got)
	}
	if got := time.Duration(fv.ttl(ifRowStateKey)) * time.Second; got <= ifRowMaxAge {
		t.Fatalf("state TTL %v does not outlive the bound %v", got, ifRowMaxAge)
	}
}

// The wire format the exporter and the topology API read has not changed.
func TestIfRowsPublishedWireFormatIsUnchanged(t *testing.T) {
	fv := newFakeValkey(t)
	targets := []Target{{ID: "a", TenantID: "t1", Address: "192.0.2.1"}}
	newRowsCollector(&targets, map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")}).pollOnce(context.Background())

	fv.mu.Lock()
	addr, index := fv.vals[ifAddrKey], fv.vals[ifIndexKey]
	fv.mu.Unlock()
	if addr != `{"a":{"10.0.0.1":"if-10.0.0.1"}}` {
		t.Fatalf("ifaddr payload: %s", addr)
	}
	if index != `{"a":{"1":"Gi1"}}` {
		t.Fatalf("ifindex payload: %s", index)
	}
}

// A restart that finds the device under a new owner must not serve the stored rows.
func TestIfRowsRestartAfterTenantChangeDiscards(t *testing.T) {
	newFakeValkey(t)
	ctx := context.Background()
	targets := []Target{{ID: "a", TenantID: "t1", Address: "192.0.2.1"}}
	newRowsCollector(&targets, map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")}).pollOnce(ctx)

	targets = []Target{{ID: "a", TenantID: "t2", Address: "192.0.2.1"}}
	newRowsCollector(&targets, map[string]deviceOutcome{}).pollOnce(ctx)

	m, err := FetchIfAddrMap(ctx)
	if err != nil {
		t.Fatalf("FetchIfAddrMap: %v", err)
	}
	if len(m["a"]) != 0 {
		t.Fatalf("rows crossed a tenant change across a restart: %v", m)
	}
}

// The last device leaving the inventory must clear the map, which is why an empty map
// is published at all.
func TestIfRowsLastDeviceRemovedClearsThePublishedMap(t *testing.T) {
	newFakeValkey(t)
	ctx := context.Background()
	targets := []Target{{ID: "a", Address: "192.0.2.1"}}
	c := newRowsCollector(&targets, map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")})
	c.pollOnce(ctx)

	targets = nil
	c.pollOnce(ctx)

	m, err := FetchIfAddrMap(ctx)
	if err != nil {
		t.Fatalf("FetchIfAddrMap: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("a removed device is still published: %v", m)
	}
}

// stubIfRowStore scripts Load and records Save.
type stubIfRowStore struct {
	load  func() (ifRowState, error)
	saved []ifRowState
}

func (s *stubIfRowStore) Load(context.Context) (ifRowState, error) { return s.load() }
func (s *stubIfRowStore) Save(_ context.Context, st ifRowState) error {
	s.saved = append(s.saved, st)
	return nil
}

// A failed read must not overwrite what it failed to read.
func TestIfRowsUnreadStateIsNotOverwrittenAndIsReadLater(t *testing.T) {
	stored := newIfRowState()
	stored.Devices["down"] = &ifRowEntry{
		Addr: ifRowSet{Rows: map[string]string{"10.0.0.9": "Gi9"}, At: time.Now().Add(-time.Hour).UnixMilli()},
	}
	fail := true
	store := &stubIfRowStore{load: func() (ifRowState, error) {
		if fail {
			return newIfRowState(), errors.New("connection refused")
		}
		return stored, nil
	}}
	targets := []Target{{ID: "down", Address: "192.0.2.1"}, {ID: "up", Address: "192.0.2.2"}}
	c := newRowsCollector(&targets, map[string]deviceOutcome{"up": answeredOutcome("10.0.0.1")})
	c.ifRowStore = store

	c.pollOnce(context.Background())
	if len(store.saved) != 0 || c.ifRowsLoaded {
		t.Fatalf("saved %d states before the stored one was read", len(store.saved))
	}

	fail = false
	c.pollOnce(context.Background())
	if !c.ifRowsLoaded || len(store.saved) != 1 {
		t.Fatalf("loaded=%v saved=%d", c.ifRowsLoaded, len(store.saved))
	}
	got := store.saved[0].Devices
	if got["down"] == nil || got["down"].Addr.Rows["10.0.0.9"] != "Gi9" {
		t.Fatalf("the late read's rows were lost: %+v", got)
	}
	if got["up"] == nil || got["up"].Addr.Rows["10.0.0.1"] == "" {
		t.Fatalf("fresh rows were lost: %+v", got)
	}
}

func TestIfRowsCorruptStateIsReportedAndReplaced(t *testing.T) {
	fv := newFakeValkey(t)
	fv.put(ifRowStateKey, "{not json")
	logs := captureIfRowLogs(t)
	targets := []Target{{ID: "a", Address: "192.0.2.1"}}
	c := newRowsCollector(&targets, map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")})

	c.pollOnce(context.Background())

	if !c.ifRowsLoaded {
		t.Fatal("corrupt bytes never improve: the collector must move on")
	}
	if fv.setCount(ifRowStateKey) != 1 {
		t.Fatal("corrupt state was not replaced")
	}
	if !logs.has("error", "unusable") {
		t.Fatalf("corrupt state was silent: %v", logs.all())
	}
}

func TestIfRowsWrongVersionIsReportedNotReinterpreted(t *testing.T) {
	fv := newFakeValkey(t)
	fv.put(ifRowStateKey, `{"version":99,"devices":{"a":{"addr":{"rows":{"10.0.0.9":"x"},"at":1}}}}`)
	targets := []Target{{ID: "a", Address: "192.0.2.1"}}
	c := newRowsCollector(&targets, map[string]deviceOutcome{})

	c.pollOnce(context.Background())

	if len(c.ifRows.Devices) != 0 {
		t.Fatalf("a foreign schema was read: %v", c.ifRows.Devices)
	}
}

// ---- observability ---------------------------------------------------------

type ifRowLogRecorder struct {
	mu  sync.Mutex
	got []string
}

func (l *ifRowLogRecorder) has(level, substr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.got {
		if strings.HasPrefix(g, level+" ") && strings.Contains(g, substr) {
			return true
		}
	}
	return false
}

func (l *ifRowLogRecorder) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.got...)
}

func captureIfRowLogs(t *testing.T) *ifRowLogRecorder {
	t.Helper()
	rec := &ifRowLogRecorder{}
	restore := applog.SetObserver(func(level, component, msg string, fields map[string]any) {
		if component != "snmpmetrics" {
			return
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.got = append(rec.got, fmt.Sprintf("%s %s %v", level, msg, fields))
	})
	t.Cleanup(restore)
	return rec
}

func TestIfRowsMetricsStateTheRetainedDevicesAndOldestAge(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	t.Setenv("VICTORIA_URL", srv.URL)
	t.Setenv("METRICS_URL", "")
	fv := newFakeValkey(t)
	ctx := context.Background()

	targets := []Target{{ID: "stale", Address: "192.0.2.1"}, {ID: "up", Address: "192.0.2.2"}}
	stored := newIfRowState()
	stored.Devices["stale"] = &ifRowEntry{
		Addr: ifRowSet{Rows: map[string]string{"10.0.0.9": "Gi9"}, At: time.Now().Add(-48 * time.Hour).UnixMilli()},
	}
	b, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fv.put(ifRowStateKey, string(b))
	newRowsCollector(&targets, map[string]deviceOutcome{"up": answeredOutcome("10.0.0.1")}).pollOnce(ctx)

	mu.Lock()
	joined := strings.Join(bodies, "\n")
	mu.Unlock()
	if !strings.Contains(joined, `collector_if_rows_retained_devices{collector="snmpmetrics"} 1 `) {
		t.Fatalf("no retained-device gauge:\n%s", joined)
	}
	var age int64
	for _, line := range strings.Split(joined, "\n") {
		if strings.HasPrefix(line, `collector_if_rows_retained_oldest_age_seconds{collector="snmpmetrics"} `) {
			if age, err = strconv.ParseInt(strings.Fields(line)[1], 10, 64); err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
		}
	}
	if age < 48*3600 || age > 48*3600+60 {
		t.Fatalf("oldest age = %ds, want 48h", age)
	}
}

func TestIfRowsMetricsReadZeroWhenEveryDeviceAnswers(t *testing.T) {
	st := newIfRowState()
	cy := applyAt(&st, ifRowsT0, answered("a", "t1", "10.0.0.1"))
	lines := ifRowMetricLines(cy, 1)
	if !strings.Contains(lines[0], "} 0 1") || !strings.Contains(lines[1], "} 0 1") {
		t.Fatalf("metrics: %v", lines)
	}
}

func TestIfRowsChangesAreLoggedOnceNotEveryCycle(t *testing.T) {
	newFakeValkey(t)
	logs := captureIfRowLogs(t)
	ctx := context.Background()
	targets := []Target{{ID: "a", Address: "192.0.2.1"}}
	script := map[string]deviceOutcome{"a": answeredOutcome("10.0.0.1")}
	c := newRowsCollector(&targets, script)
	c.pollOnce(ctx)
	if n := len(logs.all()); n != 0 {
		t.Fatalf("all answering is not news: %v", logs.all())
	}

	delete(script, "a")
	c.pollOnce(ctx)
	c.pollOnce(ctx)
	c.pollOnce(ctx)
	if n := len(logs.all()); n != 1 || !logs.has("info", "retained_devices:1") {
		t.Fatalf("want one line stating the transition, got %v", logs.all())
	}

	script["a"] = answeredOutcome("10.0.0.1")
	c.pollOnce(ctx)
	if n := len(logs.all()); n != 2 || !logs.has("info", "retained_devices:0") {
		t.Fatalf("want the recovery logged too, got %v", logs.all())
	}
}

// ---- pollDevice: what counts as an answer ----------------------------------

// fakeUDPAgent answers GET and GETNEXT from a table, over real SNMP v2c. A column
// under an entry in failing answers an error status, so its walk returns an error.
func fakeUDPAgent(t *testing.T, table map[string]berVal, failing ...[]int) string {
	t.Helper()
	type row struct {
		oid []int
		val berVal
	}
	rows := make([]row, 0, len(table))
	for dotted, v := range table {
		rows = append(rows, row{parseDottedOID(dotted), v})
	}
	less := func(a, b []int) bool {
		for i := 0; i < len(a) && i < len(b); i++ {
			if a[i] != b[i] {
				return a[i] < b[i]
			}
		}
		return len(a) < len(b)
	}
	sort.Slice(rows, func(i, j int) bool { return less(rows[i].oid, rows[j].oid) })

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			pduTag, reqID, oid, err := parseSNMPRequest(buf[:n])
			if err != nil {
				continue
			}
			var resp []byte
			for _, col := range failing {
				if oidUnder(oid, col) || reflect.DeepEqual(oid, col) {
					resp = snmpResponseErr(oid, reqID, 5)
				}
			}
			if resp == nil {
				resp = snmpResponse(oid, tagNoSuchObject, nil, reqID)
				for _, r := range rows {
					if (pduTag == 0xA0 && reflect.DeepEqual(r.oid, oid)) || (pduTag == 0xA1 && less(oid, r.oid)) {
						resp = snmpResponse(r.oid, r.val.tag, r.val.raw, reqID)
						break
					}
				}
				if pduTag == 0xA1 && len(resp) > 0 {
					if _, tag, _, ferr := firstVarbind(resp, reqID); ferr == nil && tag == tagNoSuchObject {
						resp = snmpResponse(oid, tagEndOfMibView, nil, reqID)
					}
				}
			}
			if _, err := conn.WriteTo(resp, peer); err != nil {
				return
			}
		}
	}()
	return conn.LocalAddr().String()
}

func parseSNMPRequest(pkt []byte) (pduTag byte, reqID int, oid []int, err error) {
	_, msg, _, err := readTLV(pkt)
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, msg, err = readTLV(msg) // version
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, msg, err = readTLV(msg) // community
	if err != nil {
		return 0, 0, nil, err
	}
	pduTag, pdu, _, err := readTLV(msg)
	if err != nil {
		return 0, 0, nil, err
	}
	_, id, pdu, err := readTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, pdu, err = readTLV(pdu) // error-status
	if err != nil {
		return 0, 0, nil, err
	}
	_, _, pdu, err = readTLV(pdu) // error-index
	if err != nil {
		return 0, 0, nil, err
	}
	_, vbs, _, err := readTLV(pdu)
	if err != nil {
		return 0, 0, nil, err
	}
	_, vb, _, err := readTLV(vbs)
	if err != nil {
		return 0, 0, nil, err
	}
	_, oidRaw, _, err := readTLV(vb)
	if err != nil {
		return 0, 0, nil, err
	}
	return pduTag, int(decodeInt(id)), decodeOID(oidRaw), nil
}

func dottedOID(oid []int, suffix ...int) string {
	parts := make([]string, 0, len(oid)+len(suffix))
	for _, a := range append(append([]int{}, oid...), suffix...) {
		parts = append(parts, strconv.Itoa(a))
	}
	return strings.Join(parts, ".")
}

// agentTable is one device's standard MIB answers: ifOperStatus (to trigger the
// interface path), ifName and ipAddrTable.
func agentTable(enterprise int) map[string]berVal {
	sysOID := []int{1, 3, 6, 1, 4, 1, enterprise, 1}
	return map[string]berVal{
		dottedOID(sysObjectIDOID):                   {tag: 0x06, raw: berOID(sysOID)[2:]},
		dottedOID(ifOperForTest, 1):                 {tag: 0x02, raw: []byte{1}},
		dottedOID(ifNameOID, 1):                     {tag: 0x04, raw: []byte("port-1")},
		dottedOID(ipAdEntIfIndexOID, 192, 0, 2, 33): {tag: 0x02, raw: []byte{1}},
	}
}

var ifOperForTest = []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}

func pollAgent(t *testing.T, addr string) deviceOutcome {
	t.Helper()
	c := NewSNMPMetrics(func() []Target { return nil }).(*metricsCollector)
	c.profiles = []SNMPProfile{{Name: "generic", Metrics: []SNMPMetric{{Name: "device_if_oper_status", OID: ifOperForTest, Table: true}}}}
	return c.pollDevice(context.Background(), Target{ID: "dev", Address: addr, Community: "public"})
}

// Standard IF-MIB and IP-MIB only: the answer is the same whoever made the device.
func TestPollDeviceCompleteAnswerAcrossVendors(t *testing.T) {
	for _, ent := range []int{9, 2636, 6527, 30065, 8072, 41916, 99999} {
		t.Run(strconv.Itoa(ent), func(t *testing.T) {
			r := pollAgent(t, fakeUDPAgent(t, agentTable(ent)))
			if !r.ifaddrComplete || !r.ifindexComplete {
				t.Fatalf("complete walks not recognised: %+v", r)
			}
			if r.ifaddr["192.0.2.33"] != "port-1" || r.ifindex["1"] != "port-1" {
				t.Fatalf("rows: addr=%v index=%v", r.ifaddr, r.ifindex)
			}
		})
	}
}

// The address walk failed: the device answered, but not about its addresses.
func TestPollDeviceFailedAddressWalkIsNotAnEmptyAnswer(t *testing.T) {
	r := pollAgent(t, fakeUDPAgent(t, agentTable(9), ipAdEntIfIndexOID))
	if r.ifaddrComplete {
		t.Fatal("a failed walk was taken for a device with no addresses")
	}
	if !r.ifindexComplete {
		t.Fatal("the name table did answer")
	}
}

// No name table: every address would be dropped for want of a name, which must not
// read as "the device has no addresses".
func TestPollDeviceNoNameTableIsNotAnEmptyAnswer(t *testing.T) {
	table := agentTable(9)
	delete(table, dottedOID(ifNameOID, 1))
	r := pollAgent(t, fakeUDPAgent(t, table))
	if r.ifaddrComplete || r.ifindexComplete {
		t.Fatalf("an empty name table was taken as the whole answer: %+v", r)
	}
}

// A device that really has no addresses answers an empty ipAddrTable: that removes.
func TestPollDeviceEmptyAddressTableIsAnAnswer(t *testing.T) {
	table := agentTable(9)
	delete(table, dottedOID(ipAdEntIfIndexOID, 192, 0, 2, 33))
	r := pollAgent(t, fakeUDPAgent(t, table))
	if !r.ifaddrComplete || len(r.ifaddr) != 0 {
		t.Fatalf("addr=%v complete=%v", r.ifaddr, r.ifaddrComplete)
	}
}

// One name column cut off and no other: labels yes, "the port is gone" no.
func TestIfNameMapCheckedReportsAFailedWalk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addr := fakeUDPAgent(t, agentTable(9), ifNameOID, ifDescrOID)
	if _, ok := ifNameMapChecked(ctx, addr, v2c("public")); ok {
		t.Fatal("both columns failed")
	}
	addr = fakeUDPAgent(t, agentTable(9), ifDescrOID)
	m, ok := ifNameMapChecked(ctx, addr, v2c("public"))
	if !ok || m["1"] != "port-1" {
		t.Fatalf("one complete column is the whole table: %v %v", m, ok)
	}
}
