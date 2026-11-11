// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// episodes.go — findings-on-change (owner decision D2, 2026-11-11).
//
// The lane still scans every interval and still writes every scan's verdicts to
// the findings store (the audit trail; the UI's security pages read it). What
// changed is what reaches the CORRELATION ENGINE: a standing finding is sent
// onto netops.security only when its episode APPEARS, CHANGES or CLEARS, each
// stamped with the instant the episode was first seen. A verdict the scan merely
// re-confirmed goes to netops.security.audit, which only the router reads.
//
// ── IDENTITY ────────────────────────────────────────────────────────────────
// A finding's identity is its secbus native_id:
//
//	security | kind | evidence_class | tenant | control | entity | finding id
//
// — the same key the findings store collapses `current=true` on, so "the same
// finding" means the same thing to the engine, the store and the UI. The tenant
// is a component of the key AND the outer key of every state map and store
// (§3a): two tenants with the same device and rule names never share an episode.
//
// ── MATERIAL CHANGE ─────────────────────────────────────────────────────────
// Inside an open episode a CHANGE is emitted when any of these moves:
//
//	severity · verdict (status_id) · seam_id · seam_type · internet_facing
//
// i.e. how bad it is, what the verdict is, and the exposure details. These are
// deliberately NOT material: status_detail (producer prose — advisory and
// threat details carry counts, error text and window timestamps that differ on
// every scan, which would turn every scan back into a "change"), observed
// (the config excerpt), evidence_ref (a config capture moves its locator every
// capture without the verdict moving), the resource's platform label, and the
// scan id. A verdict whose REASON changes but whose status does not is the same
// verdict; the new reason is still in the audit record for that scan.
//
// ── CLEAR ───────────────────────────────────────────────────────────────────
// An open episode clears when its finding is no longer reported BY A SOURCE THAT
// ACTUALLY RAN for it this scan. "Not reported" by a lane that failed, a device
// whose hardening evaluation errored, an advisory lane that is switched off, a
// detection read that failed or an empty inventory is not a clear — the lane did
// not look, and saying "cleared" about something nobody looked at would be the
// false clear §5g forbids. Such an episode stays open; one that stays unassessed
// for EpisodePruneAfter is dropped silently (counted), which bounds the state of
// a device that left the inventory.
//
// ── SIGNALS ARE NOT STANDING FINDINGS ───────────────────────────────────────
// evidence_class `signal` (threat detections, and the detection-window gap
// verdict) is EXEMPT from episode suppression. A signal is a dated detection
// over telemetry read exactly once (the detection high-water mark), and its
// identity is rule + device + mnemonic / conversation / source — NOT the
// occurrence. A second "new local user created" on the same device in a later
// window is a second event the engine must hear about (D1 lets a dated
// detection anchor a verdict), yet its native_id and fingerprint would match
// the first. So every signal verdict goes onto netops.security as an appear
// with first_seen = its own detection time, no episode is kept for it, and it
// never clears. An undelivered signal is preserved by the dead-letter ladder
// but not retried — the next window does not re-read that telemetry — which is
// the contract signals always had. Only posture and exposure (standing state)
// are suppressed when unchanged.
//
// ── DELIVERY ────────────────────────────────────────────────────────────────
// A transition is committed to state only once it is ON netops.security. One
// that was dead-lettered is preserved for the operator, but nothing replays
// netops.deadletter into netops.security, so the engine would never hear of it;
// one that was lost has no copy at all. Neither is committed, so the next scan
// detects and re-emits it (a re-sent verdict lands on its own scan's _id in the
// store, so the index cannot duplicate). The ts of the retry is that scan's
// verdict instant; an undelivered appear's first_seen is therefore the retry
// scan's, the one place first_seen can be later than the truth.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/secbus"
	"netops/backend/internal/secfindings"
	"netops/backend/internal/threatlane"
)

// EnvEmitClears turns on the `<kind>_clear` recovery events. Default OFF until
// the engine registers security_posture_clear / security_exposure_clear /
// security_signal_clear in signals.EVIDENCE_CLASSES["security"].kinds: an
// unregistered kind is dead-lettered by the engine and moves corr_deadletters
// (CorrDeadLettersRising). With it off a clear still CLOSES the episode (so a
// reappearance is a new episode with a new first_seen); it is only withheld from
// the bus, and counted as withheld.
const EnvEmitClears = "SECURITY_EMIT_CLEARS"

// EnvEpisodeDir is the file backend's per-tenant episode state directory, used
// when the platform runs without Postgres.
const EnvEpisodeDir = "SECURITY_EPISODE_DIR"

// DefaultEpisodeDir is the shipped EnvEpisodeDir.
const DefaultEpisodeDir = "/data/security_episodes"

// EpisodePruneAfter is how long an open episode may go UNASSESSED (its source
// never ran for it) before it is dropped from state without a clear.
//
// The clock is IN-PROCESS: "last reported" is not persisted (writing every open
// row every scan to keep it would cost far more than what it bounds), so a
// restart restarts it, and an api restarted more often than every 30 days never
// prunes. That is accepted: what lingers is only an episode whose source stopped
// running for it — in practice a device that left the inventory — so state is
// bounded by (devices ever removed × rules per device), a few hundred rows per
// removed device at most, and each lingering row is inert (it can only clear if
// that device is assessed again, which is then correct).
const EpisodePruneAfter = 30 * 24 * time.Hour

// Seed sources — the closed `source` label of the seeded counter.
const (
	SeedSourceIndex = "index" // rebuilt from the findings store's latest scan
	SeedSourceScan  = "scan"  // the index was unreadable: seeded from this scan, silently
)

// Lanes — which producing source an identity belongs to, for clear gating.
const (
	laneHardening  = "hardening"
	laneAdvisory   = "advisory"
	laneThreatLog  = "threat-log"
	laneThreatFlow = "threat-flow"
	laneGap        = "detection-gap"
)

// laneAll is the entity wildcard: the lane ran for the whole tenant.
const laneAll = "*"

// subjectStrMax / subjectTokensMax bound what one persisted subject may hold
// (§9): the strings are producer-generated, but state is still bounded storage.
const (
	subjectStrMax    = 512
	subjectTokensMax = 8
)

// Episode is one open finding episode.
type Episode struct {
	// FirstSeen is the verdict instant of the scan that opened the episode
	// (BasisObserved), or the earliest retained verdict (BasisSeed).
	FirstSeen time.Time      `json:"first_seen"`
	Basis     string         `json:"first_seen_basis"`
	Subject   EpisodeSubject `json:"subject"`
}

// EpisodeSubject is the snapshot of the last verdict the engine was told about:
// the material fields the next scan is compared against, and what a clear event
// is built from once the finding stops being reported.
type EpisodeSubject struct {
	Kind           string   `json:"kind"`
	EntityID       string   `json:"entity_id"`
	EntityType     string   `json:"entity_type,omitempty"`
	EntityTokens   []string `json:"entity_tokens,omitempty"`
	EvidenceClass  string   `json:"evidence_class,omitempty"`
	ControlID      string   `json:"control_id,omitempty"`
	RawRuleID      string   `json:"raw_rule_id,omitempty"`
	ProviderSource string   `json:"provider_source,omitempty"`
	Category       string   `json:"category,omitempty"`
	// ── material ──
	Severity       string `json:"severity,omitempty"`
	StatusID       int    `json:"status_id,omitempty"`
	SeamID         string `json:"seam_id,omitempty"`
	SeamType       string `json:"seam_type,omitempty"`
	InternetFacing bool   `json:"internet_facing,omitempty"`
}

// material is the change fingerprint: exactly the fields whose movement is a
// CHANGE (see the file comment for what is deliberately left out).
func (s EpisodeSubject) material() string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(s.Severity)),
		strconv.Itoa(s.StatusID),
		s.SeamID, s.SeamType, strconv.FormatBool(s.InternetFacing),
	}, "\x1f")
}

// lane names the source that produces this identity.
func (s EpisodeSubject) lane() string {
	return laneOf(s.ProviderSource, s.Category, s.RawRuleID)
}

// laneOf derives the producing lane from what every verdict carries, so a
// seeded episode (rebuilt from a stored document) and a live one agree.
func laneOf(providerSource, category, rawRuleID string) string {
	switch {
	case rawRuleID == detectionGapRuleID:
		return laneGap
	case providerSource == threatlane.SourceThreatLane && category == threatlane.CategoryFlow:
		return laneThreatFlow
	case providerSource == threatlane.SourceThreatLane:
		return laneThreatLog
	case providerSource == secfindings.SourceNetRule:
		return laneHardening
	default:
		return laneAdvisory
	}
}

// detectionGapRuleID is unassessedDetection's rule id.
const detectionGapRuleID = "detection-window-unassessed"

func clampStr(s string) string {
	if len(s) <= subjectStrMax {
		return s
	}
	r := []rune(s)
	if len(r) > subjectStrMax {
		r = r[:subjectStrMax]
	}
	return string(r)
}

// bounded returns the subject with every field inside the persistence bounds.
func (s EpisodeSubject) bounded() EpisodeSubject {
	s.Kind, s.EntityID, s.EntityType = clampStr(s.Kind), clampStr(s.EntityID), clampStr(s.EntityType)
	s.EvidenceClass, s.ControlID, s.RawRuleID = clampStr(s.EvidenceClass), clampStr(s.ControlID), clampStr(s.RawRuleID)
	s.ProviderSource, s.Category, s.Severity = clampStr(s.ProviderSource), clampStr(s.Category), clampStr(s.Severity)
	s.SeamID, s.SeamType = clampStr(s.SeamID), clampStr(s.SeamType)
	toks := make([]string, 0, subjectTokensMax)
	for _, t := range s.EntityTokens {
		if len(toks) == subjectTokensMax {
			break
		}
		toks = append(toks, clampStr(t))
	}
	s.EntityTokens = toks
	return s
}

func attrStr(attrs map[string]any, k string) string {
	if v, ok := attrs[k].(string); ok {
		return v
	}
	return ""
}

// attrInt reads an integer attr whether it arrived as a Go int (built here) or
// a JSON number (read back from the store).
func attrInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0
		}
		return i
	}
	return 0
}

// subjectOf snapshots one built evidence event.
func subjectOf(ev secbus.EvidenceEvent) EpisodeSubject {
	return EpisodeSubject{
		Kind:           ev.Kind,
		EntityID:       ev.EntityID,
		EntityType:     ev.EntityType,
		EntityTokens:   append([]string(nil), ev.EntityTokens...),
		EvidenceClass:  attrStr(ev.Attrs, "evidence_class"),
		ControlID:      attrStr(ev.Attrs, "control_id"),
		RawRuleID:      attrStr(ev.Attrs, "raw_rule_id"),
		ProviderSource: attrStr(ev.Attrs, "provider_source"),
		Category:       attrStr(ev.Attrs, "category"),
		Severity:       ev.Severity,
		StatusID:       attrInt(ev.Attrs["status_id"]),
		SeamID:         ev.SeamID,
		SeamType:       ev.SeamType,
		InternetFacing: ev.InternetFacing,
	}.bounded()
}

func (s EpisodeSubject) clearSubject(tenant, nativeID string) secbus.ClearSubject {
	return secbus.ClearSubject{
		TenantID: tenant, Kind: s.Kind, NativeID: nativeID,
		EntityID: s.EntityID, EntityType: s.EntityType, EntityTokens: s.EntityTokens,
		EvidenceClass: s.EvidenceClass, ControlID: s.ControlID, RawRuleID: s.RawRuleID,
		ProviderSource: s.ProviderSource, Category: s.Category,
		SeamID: s.SeamID, SeamType: s.SeamType,
	}
}

// ── persistence ─────────────────────────────────────────────────────────────

// TenantEpisodes is one tenant's stored state.
type TenantEpisodes struct {
	// Seeded is true once change tracking has started for the tenant. A tenant
	// that is not seeded is seeded from the findings store before its first
	// classified scan, so an upgrade never opens a wave of "appear" events.
	Seeded bool
	Open   map[string]Episode
}

// EpisodeCommit is one scan's delta, applied atomically.
type EpisodeCommit struct {
	Upserts map[string]Episode
	Deletes []string
	// SeedSource is set on the commit that seeds the tenant (index|scan).
	SeedSource string
}

// EpisodeStore persists per-tenant episode state so an api restart does not
// re-emit every standing finding as new.
//
// §3a: every call names ONE tenant — the tenant whose scan is running, taken
// from the tenant repo, never from input — and a store must never return or
// touch another tenant's rows (the PG store runs under the tenant_iso FORCE-RLS
// policy; the file store keys its files by tenant and verifies the owner).
//
// Load's contract mirrors Watermarks: an absent tenant is empty-and-unseeded
// with a nil error, and ANY other failure is returned — a store that answered
// "empty" to an unreadable state would re-seed silently at best and, if the
// index were also down, mask real changes.
type EpisodeStore interface {
	Load(ctx context.Context, tenant string) (TenantEpisodes, error)
	Commit(ctx context.Context, tenant string, c EpisodeCommit) error
}

// ── per-scan classification ─────────────────────────────────────────────────

// tenantTrack is the lane's in-memory view of one tenant's episodes, loaded
// once from the store and written through on every scan.
type tenantTrack struct {
	seeded   bool
	open     map[string]Episode
	lastSeen map[string]time.Time // in-memory only: when the identity was last reported
	// pending is the delta the store has not accepted yet (a refused commit, or
	// the seed); it rides along with the next commit until one succeeds.
	pending EpisodeCommit
}

// mergeCommit folds `next` onto `prev`: a later upsert overrides and un-deletes,
// a later delete removes the upsert, and a seed source sticks until committed.
func mergeCommit(prev, next EpisodeCommit) EpisodeCommit {
	out := EpisodeCommit{Upserts: map[string]Episode{}, SeedSource: prev.SeedSource}
	if next.SeedSource != "" {
		out.SeedSource = next.SeedSource
	}
	deleted := map[string]bool{}
	for _, nid := range prev.Deletes {
		deleted[nid] = true
	}
	for nid, ep := range prev.Upserts {
		out.Upserts[nid] = ep
	}
	for nid, ep := range next.Upserts {
		out.Upserts[nid] = ep
		delete(deleted, nid)
	}
	for _, nid := range next.Deletes {
		delete(out.Upserts, nid)
		deleted[nid] = true
	}
	for nid := range deleted {
		out.Deletes = append(out.Deletes, nid)
	}
	sort.Strings(out.Deletes)
	return out
}

// emitItem is one record bound for the bus, with what committing it would do.
type emitItem struct {
	nativeID   string
	transition string
	ev         secbus.EvidenceEvent
}

// scanPlan is the classification of one scan against the tenant's episodes.
type scanPlan struct {
	transitions []emitItem             // → netops.security
	unchanged   []secbus.EvidenceEvent // → netops.security.audit
	upserts     map[string]Episode
	deletes     map[string]bool
	withheld    int // clears closed in state but not emitted (EmitClears off)
	pruned      int
	counts      map[string]int // transition → planned count
}

// planScan classifies one scan. `items` are the scan's emitted (post-cap)
// events, in order; `present` holds the native_id of EVERY finding the scan
// produced, the truncated tail included, so a capped finding is never mistaken
// for a cleared one. `assessed` holds "lane|entity" and "lane|*" for every
// source that actually ran. It mutates nothing: the caller commits.
func planScan(tr *tenantTrack, tenant, scanID string, now time.Time, items []secbus.EvidenceEvent,
	present map[string]bool, assessed map[string]bool, emitClears bool) scanPlan {

	p := scanPlan{
		upserts: map[string]Episode{},
		deletes: map[string]bool{},
		counts:  map[string]int{},
	}
	for _, ev := range items {
		nid := ev.NativeID
		cur := subjectOf(ev)
		// The stamp writes into attrs; give this record its own map so the
		// caller's events are never mutated behind its back.
		attrs := make(map[string]any, len(ev.Attrs)+3)
		for k, v := range ev.Attrs {
			attrs[k] = v
		}
		ev.Attrs = attrs
		ts, err := time.Parse(time.RFC3339Nano, ev.TS)
		if err != nil {
			ts = now // FromFinding refuses a zero time, so this is unreachable in practice
		}
		prev, open := tr.open[nid]
		switch {
		case cur.EvidenceClass == secfindings.EvidenceSignal:
			// A dated detection, not a standing finding (see SIGNALS above):
			// every occurrence is its own appear, and no episode is kept.
			secbus.StampEpisode(&ev, secbus.TransitionAppear, ts.UTC(), secbus.BasisObserved)
			p.transitions = append(p.transitions, emitItem{nid, secbus.TransitionAppear, ev})
			p.counts[secbus.TransitionAppear]++
		case !open:
			ep := Episode{FirstSeen: ts.UTC(), Basis: secbus.BasisObserved, Subject: cur}
			secbus.StampEpisode(&ev, secbus.TransitionAppear, ep.FirstSeen, ep.Basis)
			p.upserts[nid] = ep
			p.transitions = append(p.transitions, emitItem{nid, secbus.TransitionAppear, ev})
			p.counts[secbus.TransitionAppear]++
		case prev.Subject.material() != cur.material():
			ep := Episode{FirstSeen: prev.FirstSeen, Basis: prev.Basis, Subject: cur}
			secbus.StampEpisode(&ev, secbus.TransitionChange, ep.FirstSeen, ep.Basis)
			p.upserts[nid] = ep
			p.transitions = append(p.transitions, emitItem{nid, secbus.TransitionChange, ev})
			p.counts[secbus.TransitionChange]++
		default:
			secbus.StampEpisode(&ev, secbus.TransitionUnchanged, prev.FirstSeen, prev.Basis)
			p.unchanged = append(p.unchanged, ev)
		}
	}
	for nid, ep := range tr.open {
		if ep.Subject.EvidenceClass == secfindings.EvidenceSignal {
			// Never tracked (a state written before signals were exempted):
			// dropped silently, never "cleared".
			p.deletes[nid] = true
			continue
		}
		if present[nid] {
			continue
		}
		lane := ep.Subject.lane()
		if !assessed[lane+"|"+laneAll] && !assessed[lane+"|"+ep.Subject.EntityID] {
			// Not looked at this scan — not a clear. Bounded by the prune.
			if seen, ok := tr.lastSeen[nid]; ok && now.Sub(seen) > EpisodePruneAfter {
				p.deletes[nid] = true
				p.pruned++
			}
			continue
		}
		p.deletes[nid] = true
		p.counts[secbus.TransitionClear]++
		if !emitClears {
			p.withheld++
			continue
		}
		ev := secbus.ClearEvent(ep.Subject.clearSubject(tenant, nid), now, scanID, ep.FirstSeen, ep.Basis)
		p.transitions = append(p.transitions, emitItem{nid, secbus.TransitionClear, ev})
	}
	return p
}

// revertLost undoes the state effect of transitions that did not reach
// netops.security (dead-lettered or lost), so the next scan detects and
// re-emits them.
func (p *scanPlan) revertLost(lost map[string]string) {
	for nid, transition := range lost {
		switch transition {
		case secbus.TransitionAppear, secbus.TransitionChange:
			delete(p.upserts, nid) // appear: never opened; change: the previous snapshot stands
		case secbus.TransitionClear:
			delete(p.deletes, nid) // still open
		}
	}
}

// apply writes the plan into the in-memory track.
func (tr *tenantTrack) apply(p scanPlan, present map[string]bool, now time.Time) {
	for nid, ep := range p.upserts {
		tr.open[nid] = ep
	}
	for nid := range p.deletes {
		delete(tr.open, nid)
		delete(tr.lastSeen, nid)
	}
	for nid := range present {
		if _, ok := tr.open[nid]; ok {
			tr.lastSeen[nid] = now
		}
	}
}

func (p scanPlan) commit() EpisodeCommit {
	c := EpisodeCommit{Upserts: p.upserts, Deletes: make([]string, 0, len(p.deletes))}
	for nid := range p.deletes {
		c.Deletes = append(c.Deletes, nid)
	}
	sort.Strings(c.Deletes)
	return c
}

// ── the lane's state access ─────────────────────────────────────────────────

// track returns the tenant's loaded episode state, loading it on first use. A
// load failure is returned and NOTHING is cached, so the next scan retries.
func (l *Lane) track(ctx context.Context, tenant string) (*tenantTrack, error) {
	l.episodesMu.Lock()
	defer l.episodesMu.Unlock()
	if tr, ok := l.tracks[tenant]; ok {
		return tr, nil
	}
	st, err := l.episodes.Load(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("security finding episode state for this tenant could not be read: %w", err)
	}
	now := l.deps.Now()
	tr := &tenantTrack{seeded: st.Seeded, open: map[string]Episode{}, lastSeen: map[string]time.Time{}}
	for nid, ep := range st.Open {
		tr.open[nid] = ep
		tr.lastSeen[nid] = now // a restart restarts the unassessed clock, never shortens it
	}
	l.tracks[tenant] = tr
	return tr, nil
}

// seed starts change tracking for a tenant that has none: the open set is
// rebuilt from the findings store's LATEST scan (what the engine was last sent
// under the old every-pass emission), so nothing already open is re-announced,
// while a finding that is new since that scan still classifies as an appear.
// If the store cannot be read the tenant is seeded from THIS scan instead —
// silent for everything in it — because a burst of thousands of "appear"
// events on upgrade is the outcome this design exists to prevent.
func (l *Lane) seed(ctx context.Context, tenant string, tr *tenantTrack, items []secbus.EvidenceEvent) (map[string]Episode, string) {
	open, err := l.seedFromIndex(ctx, tenant)
	src := SeedSourceIndex
	if err != nil {
		l.metrics.AddStateError("seed")
		l.deps.LogWarn("security finding episodes could not be seeded from the findings store — seeding from this scan, so findings already open are not re-announced but one that opened during the gap is not announced either",
			map[string]any{"tenant_seg": l.deps.TenantSeg(tenant), "err": l.deps.Scrub(err.Error())})
		src = SeedSourceScan
		open = make(map[string]Episode, len(items))
		for _, ev := range items {
			if attrStr(ev.Attrs, "evidence_class") == secfindings.EvidenceSignal {
				continue // signals are never tracked as episodes (SIGNALS)
			}
			ts, perr := time.Parse(time.RFC3339Nano, ev.TS)
			if perr != nil {
				ts = l.deps.Now()
			}
			open[ev.NativeID] = Episode{FirstSeen: ts.UTC(), Basis: secbus.BasisSeed, Subject: subjectOf(ev)}
		}
	}
	now := l.deps.Now()
	for nid, ep := range open {
		tr.open[nid] = ep
		tr.lastSeen[nid] = now
	}
	tr.seeded = true
	l.metrics.AddSeeded(src, int64(len(open)))
	return open, src
}
