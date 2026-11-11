// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// episodes_test.go — findings-on-change (owner decision D2, 2026-11-11).
//
// The two promises under test are different and both matter:
//
//   - the ENGINE hears about a standing finding only when its episode appears,
//     changes or clears (netops.security), each record stamped with first_seen;
//   - the FINDINGS STORE still receives every scan's verdicts (netops.security
//     plus netops.security.audit, both indexed by the router).
//
// fakeFindingsIndex stands in for the router + the netops-secfindings-* store:
// ingest() indexes what the lane put on either security topic exactly as the
// router would (clear kinds are not indexed), and search() answers the three
// bounded seed reads, refusing any read that names another tenant's indices.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/hardening"
	"netops/backend/internal/secbus"
	"netops/backend/secapi"
)

// ── fake findings store ─────────────────────────────────────────────────────

type fakeFindingsIndex struct {
	docs []map[string]any
	// down makes every read fail (the store is unreachable).
	down bool
	// leaks records any read whose index pattern named a tenant other than the
	// one its per-document clause filtered on.
	leaks []string
	reads int
}

func newFakeFindingsIndex() *fakeFindingsIndex { return &fakeFindingsIndex{} }

// ingest indexes records as the router does: both security topics, verdicts
// only (a clear is engine-only), ts normalised to epoch-millis.
func (x *fakeFindingsIndex) ingest(t *testing.T, recs []sentRecord) {
	t.Helper()
	for _, r := range recs {
		if r.Topic != secbus.TopicSecurityEvidence && r.Topic != secbus.TopicSecurityAudit {
			continue
		}
		ev, ok := r.Value.(secbus.EvidenceEvent)
		if !ok || secbus.IsClearKind(ev.Kind) {
			continue
		}
		raw, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		at, err := time.Parse(time.RFC3339Nano, ev.TS)
		if err != nil {
			t.Fatal(err)
		}
		doc["ts"] = float64(at.UnixMilli())
		x.docs = append(x.docs, doc)
	}
}

func jsonResp(v any) *http.Response {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}
}

func (x *fakeFindingsIndex) search(path string, body any) (*http.Response, error) {
	x.reads++
	if x.down {
		return nil, errors.New("opensearch unreachable")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var q map[string]any
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, err
	}
	tenant, prefix, scanID := "", "", ""
	var ids map[string]bool
	query, _ := q["query"].(map[string]any)
	boolQ, _ := query["bool"].(map[string]any)
	filters, _ := boolQ["filter"].([]any)
	for _, f := range filters {
		fm, _ := f.(map[string]any)
		if term, ok := fm["term"].(map[string]any); ok {
			if v, ok := term["tenant_id"].(string); ok {
				tenant = v
			}
			if v, ok := term["attrs.scan_id"].(string); ok {
				scanID = v
			}
		}
		if p, ok := fm["prefix"].(map[string]any); ok {
			prefix, _ = p["attrs.scan_id"].(string)
		}
		if terms, ok := fm["terms"].(map[string]any); ok {
			ids = map[string]bool{}
			list, _ := terms["native_id"].([]any)
			for _, v := range list {
				s, _ := v.(string)
				ids[s] = true
			}
		}
	}
	if tenant == "" {
		x.leaks = append(x.leaks, "no per-document tenant clause: "+path)
		return nil, errors.New("unscoped findings read")
	}
	if !strings.Contains(path, "netops-secfindings-"+TenantSeg(tenant)+"-*") || strings.Contains(path, "netops-secfindings-*") {
		x.leaks = append(x.leaks, path)
	}
	mine := make([]map[string]any, 0, len(x.docs))
	for _, d := range x.docs {
		if d["tenant_id"] == tenant {
			mine = append(mine, d)
		}
	}
	scanOf := func(d map[string]any) string {
		a, _ := d["attrs"].(map[string]any)
		s, _ := a["scan_id"].(string)
		return s
	}
	aggs, _ := q["aggs"].(map[string]any)
	switch {
	case aggs["latest_scan"] != nil:
		agg, _ := aggs["latest_scan"].(map[string]any)
		terms, _ := agg["terms"].(map[string]any)
		size := attrInt(terms["size"])
		seen := map[string]bool{}
		var scans []string
		for _, d := range mine {
			if s := scanOf(d); strings.HasPrefix(s, prefix) && !seen[s] {
				seen[s] = true
				scans = append(scans, s)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(scans)))
		if len(scans) > size {
			scans = scans[:size]
		}
		buckets := []any{}
		for _, s := range scans {
			buckets = append(buckets, map[string]any{"key": s})
		}
		return jsonResp(map[string]any{"aggregations": map[string]any{"latest_scan": map[string]any{"buckets": buckets}}}), nil
	case aggs["by_native"] != nil:
		mins := map[string]float64{}
		for _, d := range mine {
			nid, _ := d["native_id"].(string)
			if !ids[nid] {
				continue
			}
			ts, _ := d["ts"].(float64)
			if cur, ok := mins[nid]; !ok || ts < cur {
				mins[nid] = ts
			}
		}
		buckets := []any{}
		for nid, ts := range mins {
			buckets = append(buckets, map[string]any{"key": nid, "first": map[string]any{"value": ts}})
		}
		return jsonResp(map[string]any{"aggregations": map[string]any{"by_native": map[string]any{"buckets": buckets}}}), nil
	default:
		hits := []any{}
		for _, d := range mine {
			if scanOf(d) == scanID {
				hits = append(hits, map[string]any{"_source": d})
			}
		}
		return jsonResp(map[string]any{"hits": map[string]any{"total": map[string]any{"value": len(hits)}, "hits": hits}}), nil
	}
}

// ── fixture helpers ─────────────────────────────────────────────────────────

// memMarks is an in-memory Watermarks, so a pass never reports a detection gap
// (the gap verdict is real behaviour, but it would make every first scan carry
// one extra appear and every second scan one extra clear).
type memMarks map[string]time.Time

func (m memMarks) Load() (map[string]time.Time, error) { return cloneMarks(m), nil }
func (m memMarks) Save(tenant string, at time.Time) error {
	m[tenant] = at
	return nil
}

type episodeFixture struct {
	*laneFixture
	now   time.Time
	cfg   hardening.MemConfigSource
	store EpisodeStore
}

// newEpisodeFixture builds a lane with a movable clock, a mutable running-config
// and the given episode store (nil → a fresh in-memory one).
func newEpisodeFixture(t *testing.T, store EpisodeStore, mut func(*Deps)) *episodeFixture {
	t.Helper()
	if store == nil {
		store = NewMemEpisodes()
	}
	ef := &episodeFixture{now: fixedNow, cfg: hardening.MemConfigSource{}, store: store}
	ef.laneFixture = newFixture(t, func(d *Deps) {
		d.Now = func() time.Time { return ef.now }
		d.Interval = 15 * time.Minute
		d.Watermarks = memMarks{}
		d.Episodes = store
		d.ConfigSource = ef.cfg
		if mut != nil {
			mut(d)
		}
	})
	return ef
}

// scan runs one pass for a tenant at `at` and returns what it put on the bus.
func (ef *episodeFixture) scan(t *testing.T, tenant string, at time.Time) []sentRecord {
	t.Helper()
	before := len(ef.pub.sent)
	ef.now = at
	ef.lane.ScanTenant(context.Background(), tenant, "test")
	out := append([]sentRecord(nil), ef.pub.sent[before:]...)
	ef.index.ingest(t, out)
	return out
}

func onTopic(recs []sentRecord, topic string) []secbus.EvidenceEvent {
	var out []secbus.EvidenceEvent
	for _, r := range recs {
		if r.Topic == topic {
			out = append(out, r.Value.(secbus.EvidenceEvent))
		}
	}
	return out
}

func byNative(evs []secbus.EvidenceEvent) map[string]secbus.EvidenceEvent {
	out := map[string]secbus.EvidenceEvent{}
	for _, ev := range evs {
		out[ev.NativeID] = ev
	}
	return out
}

func ruleEvent(t *testing.T, evs []secbus.EvidenceEvent, rule string) secbus.EvidenceEvent {
	t.Helper()
	for _, ev := range evs {
		if ev.Attrs["raw_rule_id"] == rule {
			return ev
		}
	}
	t.Fatalf("no %s record among %d", rule, len(evs))
	return secbus.EvidenceEvent{}
}

const telnetRule = "telnet-vty-enabled"

const (
	cfgTelnet = "line vty 0 4\n transport input telnet\n"
	cfgSSH    = "line vty 0 4\n transport input ssh\n"
)

func stamp(ev secbus.EvidenceEvent) (transition, firstSeen, basis string) {
	transition, _ = ev.Attrs[secbus.AttrTransition].(string)
	firstSeen, _ = ev.Attrs[secbus.AttrFirstSeen].(string)
	basis, _ = ev.Attrs[secbus.AttrFirstSeenBasis].(string)
	return
}

func rfc(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

// ── appear once, then silence ───────────────────────────────────────────────

func TestUnchangedFindingAcrossScansEmitsExactlyOneAppear(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}

	const scans = 5
	appears := map[string]int{}
	var firstScan []secbus.EvidenceEvent
	for i := 0; i < scans; i++ {
		at := fixedNow.Add(time.Duration(i) * 15 * time.Minute)
		recs := ef.scan(t, "acme", at)
		engine := onTopic(recs, secbus.TopicSecurityEvidence)
		audit := onTopic(recs, secbus.TopicSecurityAudit)
		if i == 0 {
			firstScan = engine
			if len(engine) == 0 || len(audit) != 0 {
				t.Fatalf("first scan: %d engine / %d audit records, want every verdict as an appear", len(engine), len(audit))
			}
		} else if len(engine) != 0 {
			t.Fatalf("scan %d re-sent %d unchanged findings to the engine — the D2 noise is back", i+1, len(engine))
		}
		for _, ev := range engine {
			tr, fs, basis := stamp(ev)
			if tr != secbus.TransitionAppear || basis != secbus.BasisObserved {
				t.Fatalf("scan %d: %s carried transition=%q basis=%q", i+1, ev.NativeID, tr, basis)
			}
			if fs != ev.TS {
				t.Fatalf("an appear's ts must be its first_seen: ts=%s first_seen=%s", ev.TS, fs)
			}
			appears[ev.NativeID]++
		}
		for _, ev := range audit {
			tr, fs, _ := stamp(ev)
			if tr != secbus.TransitionUnchanged {
				t.Fatalf("audit record carried transition=%q", tr)
			}
			if fs != rfc(fixedNow) {
				t.Fatalf("an unchanged verdict lost its episode's first_seen: %s, want %s", fs, rfc(fixedNow))
			}
		}
	}
	if len(appears) != len(firstScan) {
		t.Fatalf("%d identities appeared, the first scan reported %d", len(appears), len(firstScan))
	}
	for nid, n := range appears {
		if n != 1 {
			t.Fatalf("%s appeared %d times across %d unchanged scans, want exactly 1", nid, n, scans)
		}
	}
	m := ef.lane.Metrics().Snapshot()
	if m["transition_appear_emitted"] != int64(len(firstScan)) {
		t.Fatalf("appear counter = %d, want %d", m["transition_appear_emitted"], len(firstScan))
	}
	if m["unchanged_suppressed_total"] != int64(len(firstScan)*(scans-1)) {
		t.Fatalf("unchanged counter = %d, want %d", m["unchanged_suppressed_total"], len(firstScan)*(scans-1))
	}
	st := ef.lane.StatusFor(secapi.Principal{Tenant: "acme"})
	if len(st) != 1 || st[0].Transitions != 0 || st[0].Unchanged != len(firstScan) || st[0].Emitted != len(firstScan) {
		t.Fatalf("status row after an unchanged scan: %+v", st)
	}
}

// TestFindingsStoreStillReceivesEveryScan: the audit trail is untouched — every
// scan's verdicts reach the store, one document per (finding, scan).
func TestFindingsStoreStillReceivesEveryScan(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme"), dev("acme-edge", "acme")}

	const scans = 4
	perScan := -1
	for i := 0; i < scans; i++ {
		if i == 2 {
			ef.cfg["acme-core"] = cfgSSH // one verdict moves mid-run
		}
		recs := ef.scan(t, "acme", fixedNow.Add(time.Duration(i)*15*time.Minute))
		verdicts := 0
		for _, ev := range append(onTopic(recs, secbus.TopicSecurityEvidence), onTopic(recs, secbus.TopicSecurityAudit)...) {
			if !secbus.IsClearKind(ev.Kind) {
				verdicts++
			}
		}
		if perScan >= 0 && verdicts != perScan {
			t.Fatalf("scan %d stored %d verdicts, scan 1 stored %d — the store must get every scan in full", i+1, verdicts, perScan)
		}
		perScan = verdicts
	}
	scansPer := map[string]map[string]bool{}
	for _, d := range ef.index.docs {
		nid, _ := d["native_id"].(string)
		a, _ := d["attrs"].(map[string]any)
		sid, _ := a["scan_id"].(string)
		if scansPer[nid] == nil {
			scansPer[nid] = map[string]bool{}
		}
		scansPer[nid][sid] = true
	}
	if len(scansPer) == 0 {
		t.Fatal("nothing reached the findings store")
	}
	for nid, s := range scansPer {
		if len(s) != scans {
			t.Fatalf("%s has %d stored scans, want %d", nid, len(s), scans)
		}
	}
}

// ── change ──────────────────────────────────────────────────────────────────

func TestVerdictChangeEmitsAChangeCarryingTheOriginalFirstSeen(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}

	t0, t1, t2 := fixedNow, fixedNow.Add(15*time.Minute), fixedNow.Add(30*time.Minute)
	ef.scan(t, "acme", t0)
	ef.scan(t, "acme", t1)
	ef.cfg["acme-core"] = cfgSSH
	recs := ef.scan(t, "acme", t2)

	engine := onTopic(recs, secbus.TopicSecurityEvidence)
	ev := ruleEvent(t, engine, telnetRule)
	tr, fs, basis := stamp(ev)
	if tr != secbus.TransitionChange {
		t.Fatalf("the telnet verdict moved and the record says %q", tr)
	}
	if fs != rfc(t0) || basis != secbus.BasisObserved {
		t.Fatalf("a change must carry the ORIGINAL first_seen %s, got %s (%s)", rfc(t0), fs, basis)
	}
	if ev.TS != rfc(t2) {
		t.Fatalf("a change's ts must be the change instant %s, got %s", rfc(t2), ev.TS)
	}
	// Only verdicts that moved are sent (the telnet exposure probe reads the
	// same vty line, so it moves too) — every record is a change, none an
	// unchanged re-send.
	for _, other := range engine {
		if tr, ofs, _ := stamp(other); tr != secbus.TransitionChange || ofs != rfc(t0) {
			t.Fatalf("%v was sent as %q (first_seen %s) alongside the change", other.Attrs["raw_rule_id"], tr, ofs)
		}
	}
	if len(engine) > 2 {
		t.Fatalf("one config line moved and %d verdicts were sent", len(engine))
	}
	// And a further unchanged scan is silent again.
	if n := len(onTopic(ef.scan(t, "acme", t2.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the scan after a change re-sent %d records", n)
	}
}

// The material rule, exercised directly: severity moves → change, with the
// episode's first_seen; a non-material field (status_detail) moves → nothing.
func TestPlanScanSeverityIsMaterialAndDetailIsNot(t *testing.T) {
	t0, t1 := fixedNow, fixedNow.Add(time.Hour)
	base := secbus.EvidenceEvent{
		SchemaVersion: "1", TenantID: "acme", TS: rfc(t1), Kind: secbus.KindPosture,
		EntityID: "acme-core", EntityType: "device", Severity: "medium", NativeID: "nid-1",
		Attrs: map[string]any{"evidence_class": "posture", "raw_rule_id": "r1", "status_id": 3,
			"provider_source": "correlix-netrule", "status_detail": "before"},
	}
	open := Episode{FirstSeen: t0, Basis: secbus.BasisObserved, Subject: subjectOf(base)}
	tr := &tenantTrack{seeded: true, open: map[string]Episode{"nid-1": open}, lastSeen: map[string]time.Time{}}

	detail := base
	detail.Attrs = map[string]any{"evidence_class": "posture", "raw_rule_id": "r1", "status_id": 3,
		"provider_source": "correlix-netrule", "status_detail": "after — different prose"}
	p := planScan(tr, "acme", "scan-x", t1, []secbus.EvidenceEvent{detail}, map[string]bool{"nid-1": true}, nil, true)
	if len(p.transitions) != 0 || len(p.unchanged) != 1 {
		t.Fatalf("a status_detail-only move must not be a change: %d transitions", len(p.transitions))
	}

	sev := base
	sev.Severity = "high"
	p = planScan(tr, "acme", "scan-x", t1, []secbus.EvidenceEvent{sev}, map[string]bool{"nid-1": true}, nil, true)
	if len(p.transitions) != 1 || p.transitions[0].transition != secbus.TransitionChange {
		t.Fatalf("a severity move must be a change: %+v", p.transitions)
	}
	if _, fs, _ := stamp(p.transitions[0].ev); fs != rfc(t0) {
		t.Fatalf("the change carried first_seen %s, want the episode's %s", fs, rfc(t0))
	}
	if p.upserts["nid-1"].FirstSeen != t0 || p.upserts["nid-1"].Subject.Severity != "high" {
		t.Fatalf("the committed episode must keep first_seen and take the new severity: %+v", p.upserts["nid-1"])
	}
	if sev.Attrs[secbus.AttrTransition] != nil {
		t.Fatal("planScan stamped the CALLER's event map — records must get their own attrs")
	}

	for name, mutate := range map[string]func(*secbus.EvidenceEvent){
		"status":          func(e *secbus.EvidenceEvent) { e.Attrs["status_id"] = 1 },
		"seam_id":         func(e *secbus.EvidenceEvent) { e.SeamID = "seam-9" },
		"seam_type":       func(e *secbus.EvidenceEvent) { e.SeamType = "ISP" },
		"internet_facing": func(e *secbus.EvidenceEvent) { e.InternetFacing = true },
	} {
		ev := base
		ev.Attrs = map[string]any{}
		for k, v := range base.Attrs {
			ev.Attrs[k] = v
		}
		mutate(&ev)
		p := planScan(tr, "acme", "scan-x", t1, []secbus.EvidenceEvent{ev}, map[string]bool{"nid-1": true}, nil, true)
		if len(p.transitions) != 1 || p.transitions[0].transition != secbus.TransitionChange {
			t.Errorf("%s moved and no change was planned", name)
		}
	}
}

// ── clear, and the next episode ─────────────────────────────────────────────

func TestFindingGoneForOneScanClearsAndReturnsAsANewEpisode(t *testing.T) {
	ef := newEpisodeFixture(t, nil, func(d *Deps) { d.EmitClears = true })
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}

	t0, t1, t2 := fixedNow, fixedNow.Add(15*time.Minute), fixedNow.Add(30*time.Minute)
	first := ruleEvent(t, onTopic(ef.scan(t, "acme", t0), secbus.TopicSecurityEvidence), telnetRule)

	ef.states["acme"] = map[string]bool{telnetRule: false} // no longer reported
	engine := onTopic(ef.scan(t, "acme", t1), secbus.TopicSecurityEvidence)
	if len(engine) != 1 {
		t.Fatalf("the scan the finding vanished in sent %d records, want exactly its clear", len(engine))
	}
	clr := engine[0]
	if clr.Kind != secbus.ClearKind(first.Kind) || clr.NativeID != first.NativeID || clr.EntityID != first.EntityID {
		t.Fatalf("clear kind/identity/entity = %s/%s/%s, want %s/%s/%s",
			clr.Kind, clr.NativeID, clr.EntityID, secbus.ClearKind(first.Kind), first.NativeID, first.EntityID)
	}
	tr, fs, _ := stamp(clr)
	if tr != secbus.TransitionClear || fs != rfc(t0) || clr.TS != rfc(t1) || clr.Severity != "info" {
		t.Fatalf("clear = transition %q first_seen %s ts %s severity %s", tr, fs, clr.TS, clr.Severity)
	}
	if _, has := clr.Attrs["status"]; has {
		t.Fatal("a clear states no verdict — the finding was not reported")
	}

	delete(ef.states, "acme")
	back := ruleEvent(t, onTopic(ef.scan(t, "acme", t2), secbus.TopicSecurityEvidence), telnetRule)
	tr, fs, _ = stamp(back)
	if tr != secbus.TransitionAppear || fs != rfc(t2) {
		t.Fatalf("the reappearance must be a NEW episode (appear, first_seen %s), got %q %s", rfc(t2), tr, fs)
	}
	if ef.lane.Metrics().Snapshot()["transition_clear_emitted"] != 1 {
		t.Fatal("the emitted clear was not counted")
	}
}

func TestClearsAreWithheldByDefaultButStillCloseTheEpisode(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil) // EmitClears off: the shipped default
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}

	ef.scan(t, "acme", fixedNow)
	ef.states["acme"] = map[string]bool{telnetRule: false}
	if n := len(onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("%d records reached the engine with clears switched off (the engine dead-letters an unregistered kind)", n)
	}
	if got := ef.lane.Metrics().Snapshot()["transition_clear_withheld"]; got != 1 {
		t.Fatalf("withheld clears = %d, want 1", got)
	}
	delete(ef.states, "acme")
	t2 := fixedNow.Add(30 * time.Minute)
	back := ruleEvent(t, onTopic(ef.scan(t, "acme", t2), secbus.TopicSecurityEvidence), telnetRule)
	if tr, fs, _ := stamp(back); tr != secbus.TransitionAppear || fs != rfc(t2) {
		t.Fatalf("a withheld clear must still close the episode: got %q first_seen %s", tr, fs)
	}
}

// A source that did not run is not a clear: an empty inventory (e.g. not yet
// loaded) must not close anything, and an episode that stays unassessed past
// EpisodePruneAfter is dropped silently rather than "cleared".
func TestUnassessedIsNeverACleared(t *testing.T) {
	ef := newEpisodeFixture(t, nil, func(d *Deps) { d.EmitClears = true })
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}
	opened := len(onTopic(ef.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence))

	ef.devices["acme"] = nil
	if n := len(onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("an EMPTY inventory cleared %d findings — nothing was assessed", n)
	}
	st, _ := ef.store.Load(context.Background(), "acme")
	if len(st.Open) != opened {
		t.Fatalf("unassessed episodes were dropped from state: %d open, want %d", len(st.Open), opened)
	}

	recs := ef.scan(t, "acme", fixedNow.Add(EpisodePruneAfter+time.Hour))
	if n := len(onTopic(recs, secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the prune emitted %d records — it is silent by design", n)
	}
	st, _ = ef.store.Load(context.Background(), "acme")
	if len(st.Open) != 0 {
		t.Fatalf("%d episodes survived %s unassessed", len(st.Open), EpisodePruneAfter)
	}
	if got := ef.lane.Metrics().Snapshot()["episodes_pruned_total"]; got != int64(opened) {
		t.Fatalf("pruned = %d, want %d", got, opened)
	}
}

// A hardening evaluation that errors for a device is not a clear either.
type failingConfig struct{ fail bool }

func (f *failingConfig) RunningConfig(context.Context, string) (string, bool, error) {
	if f.fail {
		return "", false, errors.New("config store unreachable")
	}
	return cfgTelnet, true, nil
}

func TestHardeningFailureForADeviceDoesNotClearItsEpisodes(t *testing.T) {
	cfg := &failingConfig{}
	ef := newEpisodeFixture(t, nil, func(d *Deps) { d.EmitClears = true; d.ConfigSource = cfg })
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}
	ef.scan(t, "acme", fixedNow)

	cfg.fail = true
	for _, ev := range onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence) {
		if secbus.IsClearKind(ev.Kind) && ev.Attrs["provider_source"] == "correlix-netrule" {
			t.Fatalf("a FAILED hardening evaluation cleared %v", ev.Attrs["raw_rule_id"])
		}
	}
}

// The truncated tail is present, so it is never cleared.
func TestTruncatedFindingsAreNotCleared(t *testing.T) {
	store := NewMemEpisodes()
	wide := newEpisodeFixture(t, store, func(d *Deps) { d.EmitClears = true })
	wide.cfg["acme-core"] = cfgTelnet
	wide.devices["acme"] = []Device{dev("acme-core", "acme")}
	opened := len(onTopic(wide.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence))

	narrow := newEpisodeFixture(t, store, func(d *Deps) { d.EmitClears = true; d.MaxFindings = 3 })
	narrow.cfg["acme-core"] = cfgTelnet
	narrow.devices["acme"] = []Device{dev("acme-core", "acme")}
	narrow.index = wide.index
	for _, ev := range onTopic(narrow.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence) {
		if secbus.IsClearKind(ev.Kind) {
			t.Fatalf("a finding cut by the per-run cap was cleared: %s", ev.NativeID)
		}
	}
	st, _ := store.Load(context.Background(), "acme")
	if len(st.Open) != opened {
		t.Fatalf("%d episodes open after a truncated run, want %d", len(st.Open), opened)
	}
}

// ── delivery ────────────────────────────────────────────────────────────────

func TestLostTransitionIsRetriedNextScanAndDeadLetteredIsNot(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}

	// Scan 1: every sink refuses — the appears have no durable copy.
	ef.pub.failTopics[secbus.TopicSecurityEvidence] = errors.New("bus bridge 503")
	ef.pub.failTopics[DeadLetterTopic] = errors.New("bus bridge 503")
	ef.spoolErr = errors.New("disk full")
	ef.scan(t, "acme", fixedNow)
	if got := ef.lane.Metrics().Snapshot()["transition_appear_lost"]; got == 0 {
		t.Fatal("lost appears were not counted")
	}

	// Scan 2: the bus is back — the lost appears are detected and sent again.
	delete(ef.pub.failTopics, secbus.TopicSecurityEvidence)
	delete(ef.pub.failTopics, DeadLetterTopic)
	ef.spoolErr = nil
	t1 := fixedNow.Add(15 * time.Minute)
	engine := onTopic(ef.scan(t, "acme", t1), secbus.TopicSecurityEvidence)
	if len(engine) == 0 {
		t.Fatal("a LOST appear was never re-sent — the engine will never hear of these findings")
	}
	for _, ev := range engine {
		if tr, _, _ := stamp(ev); tr != secbus.TransitionAppear {
			t.Fatalf("the retry must be an appear, got %q", tr)
		}
	}

	// Scan 3 with a DEAD-LETTERED change: preserved, so it is not re-sent.
	ef.cfg["acme-core"] = cfgSSH
	ef.pub.failTopics[secbus.TopicSecurityEvidence] = errors.New("bus bridge 503")
	ef.scan(t, "acme", t1.Add(15*time.Minute))
	delete(ef.pub.failTopics, secbus.TopicSecurityEvidence)
	if n := len(onTopic(ef.scan(t, "acme", t1.Add(30*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("a change preserved in the dead-letter topic was re-sent (%d records) — the ladder is the durable copy", n)
	}
}

// ── persistence across a restart ────────────────────────────────────────────

func TestRestartWithPersistedStateReEmitsNothing(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T) EpisodeStore{
		"file": func(t *testing.T) EpisodeStore { return NewFileEpisodes(t.TempDir(), TenantSeg) },
		"mem":  func(*testing.T) EpisodeStore { return NewMemEpisodes() },
	} {
		t.Run(name, func(t *testing.T) {
			store := mk(t)
			before := newEpisodeFixture(t, store, nil)
			before.cfg["acme-core"] = cfgTelnet
			before.devices["acme"] = []Device{dev("acme-core", "acme")}
			opened := len(onTopic(before.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence))
			before.scan(t, "acme", fixedNow.Add(15*time.Minute))

			if fe, ok := store.(*FileEpisodes); ok {
				// A new process: nothing cached, only what is on disk.
				store = NewFileEpisodes(fe.dir, TenantSeg)
			}
			after := newEpisodeFixture(t, store, nil)
			after.cfg["acme-core"] = cfgTelnet
			after.devices["acme"] = []Device{dev("acme-core", "acme")}
			after.index.down = true // a seed would have to fail over; state must make it unnecessary
			recs := after.scan(t, "acme", fixedNow.Add(2*time.Hour))
			if n := len(onTopic(recs, secbus.TopicSecurityEvidence)); n != 0 {
				t.Fatalf("a restart re-announced %d findings as new", n)
			}
			audit := onTopic(recs, secbus.TopicSecurityAudit)
			if len(audit) != opened {
				t.Fatalf("after the restart %d verdicts were stored, want %d", len(audit), opened)
			}
			for _, ev := range audit {
				if _, fs, basis := stamp(ev); fs != rfc(fixedNow) || basis != secbus.BasisObserved {
					t.Fatalf("first_seen did not survive the restart: %s (%s)", fs, basis)
				}
			}
			if after.index.reads != 0 {
				t.Fatalf("a seeded tenant re-read the findings store %d times on restart", after.index.reads)
			}
		})
	}
}

// ── upgrade: the silent seed ────────────────────────────────────────────────

func TestUpgradeSeedsSilentlyFromTheStoreAndStillAnnouncesWhatIsNew(t *testing.T) {
	// Before the upgrade: two scans' worth of history in the findings store.
	legacy := newEpisodeFixture(t, nil, nil)
	legacy.cfg["acme-core"] = cfgTelnet
	legacy.devices["acme"] = []Device{dev("acme-core", "acme")}
	tOld := fixedNow.Add(-2 * time.Hour)
	legacy.scan(t, "acme", tOld)
	legacy.scan(t, "acme", fixedNow.Add(-time.Hour))

	// After the upgrade: an empty episode store, the same findings store, and
	// a device that is new since the last stored scan.
	up := newEpisodeFixture(t, NewMemEpisodes(), nil)
	up.index = legacy.index
	up.cfg["acme-core"] = cfgTelnet
	up.cfg["acme-edge"] = cfgTelnet
	up.devices["acme"] = []Device{dev("acme-core", "acme"), dev("acme-edge", "acme")}
	recs := up.scan(t, "acme", fixedNow)

	engine := onTopic(recs, secbus.TopicSecurityEvidence)
	if len(engine) == 0 {
		t.Fatal("the new device's findings were swallowed by the seed")
	}
	for _, ev := range engine {
		if ev.EntityID != "acme-edge" {
			t.Fatalf("the upgrade re-announced an ALREADY-OPEN finding on %s (%v)", ev.EntityID, ev.Attrs["raw_rule_id"])
		}
		if tr, _, _ := stamp(ev); tr != secbus.TransitionAppear {
			t.Fatalf("new finding sent as %q", tr)
		}
	}
	for _, ev := range onTopic(recs, secbus.TopicSecurityAudit) {
		if ev.EntityID != "acme-core" {
			t.Fatalf("audit carried %s", ev.EntityID)
		}
		if _, fs, basis := stamp(ev); basis != secbus.BasisSeed || fs != rfc(tOld) {
			t.Fatalf("a seeded episode must carry basis=seed and the earliest stored verdict %s, got %s (%s)", rfc(tOld), fs, basis)
		}
	}
	if len(up.index.leaks) != 0 {
		t.Fatalf("the seed read another tenant's indices: %v", up.index.leaks)
	}
	if up.lane.Metrics().Snapshot()["episodes_seeded_index"] == 0 {
		t.Fatal("the index seed was not counted")
	}
	// A seeded tenant is marked: the next scan does not seed again.
	reads := up.index.reads
	up.scan(t, "acme", fixedNow.Add(15*time.Minute))
	if up.index.reads != reads {
		t.Fatal("a seeded tenant was seeded again")
	}
}

// An upgrade whose first scan ran with episode state unreadable stored that
// scan as "unclassified"; the seed steps back past it to the newest scan the
// engine actually received, so what was already open stays silent.
func TestSeedStepsBackPastAnUnclassifiedScan(t *testing.T) {
	legacy := newEpisodeFixture(t, nil, nil)
	legacy.cfg["acme-core"] = cfgTelnet
	legacy.devices["acme"] = []Device{dev("acme-core", "acme")}
	legacy.scan(t, "acme", fixedNow.Add(-time.Hour))

	store := &flakyStore{MemEpisodes: NewMemEpisodes(), loadErr: errors.New("pg down")}
	up := newEpisodeFixture(t, store, nil)
	up.index = legacy.index
	up.cfg["acme-core"] = cfgTelnet
	up.devices["acme"] = []Device{dev("acme-core", "acme")}
	up.scan(t, "acme", fixedNow) // unclassified, audit only

	store.loadErr = nil
	if n := len(onTopic(up.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the seed read the UNCLASSIFIED scan as unknown-to-the-engine and re-announced %d findings", n)
	}
}

func TestSeedFallsBackToThisScanWhenTheStoreIsUnreadable(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}
	ef.index.down = true
	recs := ef.scan(t, "acme", fixedNow)
	if n := len(onTopic(recs, secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("an unreadable store turned the upgrade into a burst of %d appears", n)
	}
	m := ef.lane.Metrics().Snapshot()
	if m["episodes_seeded_scan"] == 0 || m["episode_state_errors_seed"] != 1 {
		t.Fatalf("the fallback seed was not observable: %+v", m)
	}
	// Tracking proceeds normally from there.
	ef.cfg["acme-core"] = cfgSSH
	ev := ruleEvent(t, onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence), telnetRule)
	if tr, fs, basis := stamp(ev); tr != secbus.TransitionChange || fs != rfc(fixedNow) || basis != secbus.BasisSeed {
		t.Fatalf("after a scan seed: %q %s %s", tr, fs, basis)
	}
}

// A seed whose first-seen read fails keeps the latest stored verdict's time.
func TestSeedReadIsRefusedWhenItCannotBeComplete(t *testing.T) {
	ef := newEpisodeFixture(t, nil, nil)
	if _, err := ef.lane.seedFromIndex(context.Background(), "acme"); err != nil {
		t.Fatalf("an empty store is an empty seed, not an error: %v", err)
	}
	// A docs page shorter than its total is incomplete.
	ef.lane.deps.Search = func(_, path string, body any) (*http.Response, error) {
		raw, _ := json.Marshal(body)
		if strings.Contains(string(raw), "latest_scan") {
			return jsonResp(map[string]any{"aggregations": map[string]any{"latest_scan": map[string]any{
				"buckets": []any{map[string]any{"key": "scan-acme-x"}}}}}), nil
		}
		return jsonResp(map[string]any{"hits": map[string]any{"total": map[string]any{"value": 20000}, "hits": []any{}}}), nil
	}
	if _, err := ef.lane.seedFromIndex(context.Background(), "acme"); err == nil {
		t.Fatal("an incomplete seed page must be refused — a partial seed announces the rest as new")
	}
	ef.lane.deps.Search = func(string, string, any) (*http.Response, error) { return jsonResp(map[string]any{}), nil }
	if _, err := ef.lane.seedFromIndex(context.Background(), "acme"); err == nil {
		t.Fatal("a reply with no aggregation must be refused, not read as an empty store")
	}
}

// ── state failures ──────────────────────────────────────────────────────────

type flakyStore struct {
	*MemEpisodes
	loadErr, commitErr error
	commits            int
}

func (f *flakyStore) Load(ctx context.Context, tenant string) (TenantEpisodes, error) {
	if f.loadErr != nil {
		return TenantEpisodes{}, f.loadErr
	}
	return f.MemEpisodes.Load(ctx, tenant)
}

func (f *flakyStore) Commit(ctx context.Context, tenant string, c EpisodeCommit) error {
	f.commits++
	if f.commitErr != nil {
		return f.commitErr
	}
	return f.MemEpisodes.Commit(ctx, tenant, c)
}

func TestUnreadableStateSendsEverythingToTheStoreAndNothingToTheEngine(t *testing.T) {
	store := &flakyStore{MemEpisodes: NewMemEpisodes(), loadErr: errors.New("pg down")}
	ef := newEpisodeFixture(t, store, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}
	recs := ef.scan(t, "acme", fixedNow)
	if n := len(onTopic(recs, secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("with episode state unreadable %d records reached the engine", n)
	}
	audit := onTopic(recs, secbus.TopicSecurityAudit)
	if len(audit) == 0 {
		t.Fatal("the findings store lost a scan because episode state was unreadable")
	}
	for _, ev := range audit {
		if tr, fs, _ := stamp(ev); tr != secbus.TransitionUnclassified || fs != "" {
			t.Fatalf("a verdict stored without state must say so (unclassified, no first_seen): %q %q", tr, fs)
		}
	}
	st := ef.lane.StatusFor(secapi.Principal{Tenant: "acme"})
	if st[0].Outcome != OutcomePartial || !strings.Contains(strings.Join(st[0].Errors, "|"), "episode-state") {
		t.Fatalf("the degradation is not on the status row: %+v", st[0])
	}
	if ef.lane.Metrics().Snapshot()["episode_state_errors_load"] != 1 {
		t.Fatal("the load failure was not counted")
	}
	store.loadErr = nil
	if n := len(onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n == 0 {
		t.Fatal("once state is readable the lane must classify again (empty store → appears)")
	}
}

func TestRefusedCommitIsCarriedForward(t *testing.T) {
	store := &flakyStore{MemEpisodes: NewMemEpisodes(), commitErr: errors.New("pg down")}
	ef := newEpisodeFixture(t, store, nil)
	ef.cfg["acme-core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("acme-core", "acme")}
	opened := len(onTopic(ef.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence))
	if ef.lane.Metrics().Snapshot()["episode_state_errors_commit"] != 1 {
		t.Fatal("the refused commit was not counted")
	}
	store.commitErr = nil
	if n := len(onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)); n != 0 {
		t.Fatalf("the in-memory view must stand after a refused commit; %d re-sent", n)
	}
	st, err := store.MemEpisodes.Load(context.Background(), "acme")
	if err != nil || !st.Seeded || len(st.Open) != opened {
		t.Fatalf("the carried-forward commit did not land: seeded=%v open=%d want %d (%v)", st.Seeded, len(st.Open), opened, err)
	}
}

// ── §3a ─────────────────────────────────────────────────────────────────────

// Two tenants with the SAME device id and the same rules: their episodes are
// independent — a change or clear in one never moves the other, identities never
// collide, and the store never hands one tenant the other's rows.
func TestEpisodesOfTwoTenantsWithIdenticalNamesAreIndependent(t *testing.T) {
	store := NewFileEpisodes(t.TempDir(), TenantSeg)
	ef := newEpisodeFixture(t, store, func(d *Deps) { d.EmitClears = true })
	ef.cfg["core"] = cfgTelnet
	ef.devices["acme"] = []Device{dev("core", "acme")}
	ef.devices["globex"] = []Device{dev("core", "globex")}

	a := byNative(onTopic(ef.scan(t, "acme", fixedNow), secbus.TopicSecurityEvidence))
	g := byNative(onTopic(ef.scan(t, "globex", fixedNow), secbus.TopicSecurityEvidence))
	if len(a) == 0 || len(a) != len(g) {
		t.Fatalf("acme opened %d, globex %d — identical estates must open the same count", len(a), len(g))
	}
	for nid := range a {
		if _, clash := g[nid]; clash {
			t.Fatalf("TENANT COLLISION: %s is one identity in two tenants", nid)
		}
	}

	ef.states["globex"] = map[string]bool{telnetRule: false}
	gRecs := onTopic(ef.scan(t, "globex", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)
	aRecs := onTopic(ef.scan(t, "acme", fixedNow.Add(15*time.Minute)), secbus.TopicSecurityEvidence)
	if len(gRecs) != 1 || !secbus.IsClearKind(gRecs[0].Kind) || gRecs[0].TenantID != "globex" {
		t.Fatalf("globex's own clear: %+v", gRecs)
	}
	if len(aRecs) != 0 {
		t.Fatalf("TENANT LEAK: globex disabling a rule moved acme's episodes (%d records)", len(aRecs))
	}

	for tenant, want := range map[string]int{"acme": len(a), "globex": len(g) - 1} {
		st, err := store.Load(context.Background(), tenant)
		if err != nil || len(st.Open) != want {
			t.Fatalf("%s state: %d open (%v), want %d", tenant, len(st.Open), err, want)
		}
		for nid := range st.Open {
			if !strings.Contains(nid, "|"+tenant+"|") {
				t.Fatalf("TENANT LEAK: %s's store returned %s", tenant, nid)
			}
		}
	}
	if len(ef.index.leaks) != 0 {
		t.Fatalf("a seed read named another tenant's indices: %v", ef.index.leaks)
	}
}

func TestFileEpisodesRefusesAFileOwnedByAnotherTenant(t *testing.T) {
	dir := t.TempDir()
	// Two ids that render to the same file token must never read each other.
	seg := func(string) string { return "same" }
	a := NewFileEpisodes(dir, seg)
	if err := a.Commit(context.Background(), "acme", EpisodeCommit{
		Upserts: map[string]Episode{"nid": {FirstSeen: fixedNow, Subject: EpisodeSubject{Kind: "security_posture"}}},
	}); err != nil {
		t.Fatal(err)
	}
	b := NewFileEpisodes(dir, seg)
	if _, err := b.Load(context.Background(), "globex"); err == nil {
		t.Fatal("TENANT LEAK: globex loaded a state file owned by acme")
	}
	if err := b.Commit(context.Background(), "globex", EpisodeCommit{}); err == nil {
		t.Fatal("globex overwrote a state file owned by acme")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "same.json"))
	if err != nil || !strings.Contains(string(raw), `"tenant":"acme"`) {
		t.Fatalf("acme's file must be intact: %s (%v)", raw, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "same.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := NewFileEpisodes(dir, func(string) string { return "../x" }).Load(context.Background(), "acme"); err == nil {
		t.Fatal("a path-shaped tenant segment must be refused")
	}
}

func TestMergeCommitKeepsTheLatestWord(t *testing.T) {
	ep := func(sev string) Episode { return Episode{Subject: EpisodeSubject{Severity: sev}} }
	got := mergeCommit(
		EpisodeCommit{Upserts: map[string]Episode{"a": ep("low"), "b": ep("low")}, Deletes: []string{"c"}, SeedSource: SeedSourceIndex},
		EpisodeCommit{Upserts: map[string]Episode{"a": ep("high"), "c": ep("low")}, Deletes: []string{"b"}},
	)
	if got.Upserts["a"].Subject.Severity != "high" || got.SeedSource != SeedSourceIndex {
		t.Fatalf("merge: %+v", got)
	}
	if _, ok := got.Upserts["b"]; ok {
		t.Fatal("a later delete must remove the earlier upsert")
	}
	if _, ok := got.Upserts["c"]; !ok {
		t.Fatal("a later upsert must override the earlier delete")
	}
	sort.Strings(got.Deletes)
	if strings.Join(got.Deletes, ",") != "b" {
		t.Fatalf("deletes = %v, want [b]", got.Deletes)
	}
}

func TestLaneOfAgreesForLiveAndSeededIdentities(t *testing.T) {
	for _, c := range []struct{ src, cat, rule, want string }{
		{"correlix-netrule", "", "telnet-vty-enabled", laneHardening},
		{"correlix-netrule", "", detectionGapRuleID, laneGap},
		{"correlix-threatlane", "flow", "flow-beaconing", laneThreatFlow},
		{"correlix-threatlane", "device-log", "log-new-local-user", laneThreatLog},
		{"vendor-api", "vulnerability", "advisory-unassessed", laneAdvisory},
		{"offline-feed", "", "CVE-2026-0001", laneAdvisory},
	} {
		if got := laneOf(c.src, c.cat, c.rule); got != c.want {
			t.Errorf("laneOf(%s,%s,%s) = %s, want %s", c.src, c.cat, c.rule, got, c.want)
		}
	}
}
