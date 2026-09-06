// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alerts

// episodes.go — alert EPISODE grouping + triage state (cloud-platform backlog
// Wave 2 #6, product-review rev #7 + missing #4/#5), extracted from package
// main (Phase-2 W1.3).
//
// Repeated firings of the same (tenant, resource, signal, state) fold into ONE
// episode carrying first_seen/last_seen/count, so an incident storm reads as a
// handful of episodes instead of a wall of identical rows. The engine feeds
// transitions through Engine.OnTransition; this layer NEVER changes what fires
// or what the /api/alerts surface serves — it groups on top.
//
// Lifecycle: an episode is `active` while its alert fires, `cleared` when it
// resolves, and `closed` once it has stayed quiet past the close window. A
// re-fire while cleared folds into the same episode (count+1); a re-fire after
// close starts a NEW episode. An episode that flips state N times inside the
// flap window is marked `flapping` — visibly, never silently suppressed.
//
// Tenancy (§3a): an episode's tenant is derived from its device at fold time
// by the CALLER (device-less/stack episodes are platform-owned, tenant "").
// Reads mirror the /api/alerts rule — a scoped principal sees its own tenant's
// episodes plus device-less ones; writes are strictly own-tenant (cross-tenant
// id → ErrEpisodeNotFound so existence is never revealed).
//
// The env knobs (ALERT_EPISODE_*) are read by main and passed to the
// constructor — env reads stay in the entrypoint per the decomposition rules.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

const (
	EpisodeStatusActive  = "active"
	EpisodeStatusCleared = "cleared"
	EpisodeStatusClosed  = "closed"

	// EpisodeMaxNotes / EpisodeMaxNoteChars / EpisodeMaxSnoozeAhead bound the
	// triage surface; the HTTP handler validates against them so its error
	// messages and this store can never disagree.
	EpisodeMaxNotes       = 50   // notes per episode
	EpisodeMaxNoteChars   = 2000 // characters per note
	EpisodeMaxSnoozeAhead = 7 * 24 * time.Hour

	episodeMaxPerTenant  = 500 // per-tenant retention cap; oldest closed evicted first
	episodeMaxFlipsKept  = 64  // flip-timestamp ring (flap detection only needs the window)
	episodeDefaultLimit  = 200 // list default
	episodeMaxQueryLimit = 500 // list hard cap (disclosed via `truncated`)
)

// ErrEpisodeNotFound is returned for an absent id AND for another tenant's id —
// the two must be indistinguishable (§3a: existence is never revealed).
var ErrEpisodeNotFound = errors.New("episode not found")

// EpisodeNote is one triage annotation (who/when/what).
type EpisodeNote struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Text string    `json:"text"`
}

// Episode is the folded view of repeated firings of one
// (tenant, resource, signal, state) plus its triage state.
type Episode struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id,omitempty"`
	Resource string `json:"resource,omitempty"` // device id; "" = platform/stack-level
	Signal   string `json:"signal"`             // rule name
	State    string `json:"state"`              // normalized severity (critical|warning|…)
	Summary  string `json:"summary,omitempty"`  // latest rendered summary

	Status    string    `json:"status"` // active | cleared | closed
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"` // last observed transition (fire or clear)
	Count     int       `json:"count"`     // number of firings folded in
	Flapping  bool      `json:"flapping"`  // hit the flip threshold inside the flap window
	FlipCount int       `json:"flip_count"`

	// Triage state. Actor fields are stamped server-side from the principal.
	AcknowledgedBy string        `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time    `json:"acknowledged_at,omitempty"`
	AssignedTo     string        `json:"assigned_to,omitempty"`
	AssignedBy     string        `json:"assigned_by,omitempty"`
	Muted          bool          `json:"muted,omitempty"`
	MutedBy        string        `json:"muted_by,omitempty"`
	SnoozedUntil   *time.Time    `json:"snoozed_until,omitempty"`
	SnoozedBy      string        `json:"snoozed_by,omitempty"`
	Notes          []EpisodeNote `json:"notes,omitempty"`

	// Flips holds recent state-transition timestamps for flap detection. Kept in
	// the persisted form so flap state survives a restart; trimmed to the ring cap.
	Flips []time.Time `json:"flips,omitempty"`
}

// suppressed reports whether the episode's notifications are currently paused.
func (ep *Episode) suppressed(now time.Time) bool {
	return ep.Muted || (ep.SnoozedUntil != nil && now.Before(*ep.SnoozedUntil))
}

func episodeKey(tenant, resource, signal, state string) string {
	return tenant + "\x1f" + resource + "\x1f" + signal + "\x1f" + state
}

// sameTenant mirrors main's sameTenantStrict rule for an already-scoped
// principal (case/space-insensitive exact match; duplicated at the boundary
// per the no-utils rule — the cross-tenant short-circuit stays with the caller).
func sameTenant(resourceTenant, principalTenant string) bool {
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(principalTenant))
}

// episodeID mints a random 8-byte hex id (main's randHex, duplicated).
func episodeID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is a platform fault; an empty id would collide in
		// the map, so fall back to a time-derived id and say so.
		applog.Error("alerts", "episode id entropy failed", map[string]any{"err": err.Error()})
		return "t" + time.Now().UTC().Format("150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// EpisodeStore folds alert transitions into episodes. File-backed like the
// rest of the alerts-adjacent state (bounded, tenant-scoped in-store); the
// engine's transitions are tick-grained, so the write rate is low.
type EpisodeStore struct {
	mu       sync.RWMutex
	path     string
	episodes map[string]*Episode // id → episode
	open     map[string]string   // fold key → id of the NOT-closed episode

	closeWindow time.Duration
	flapFlips   int
	flapWindow  time.Duration

	now func() time.Time // test seam (SetNowForTest)
}

// NewEpisodeStore loads persisted episodes. The fold knobs are the caller's:
// closeWindow (quiet gap that closes a cleared episode), flapFlips/flapWindow
// (N flips in M marks the episode flapping). Zero/negative knobs take the
// documented defaults (15m / 6 / 15m); flapFlips is floored at 2 — below that
// every clear would count as a flap.
func NewEpisodeStore(path string, closeWindow time.Duration, flapFlips int, flapWindow time.Duration) *EpisodeStore {
	if closeWindow <= 0 {
		closeWindow = 15 * time.Minute
	}
	if flapWindow <= 0 {
		flapWindow = 15 * time.Minute
	}
	if flapFlips <= 0 {
		flapFlips = 6
	}
	if flapFlips < 2 {
		flapFlips = 2
	}
	s := &EpisodeStore{
		path:        path,
		episodes:    map[string]*Episode{},
		open:        map[string]string{},
		closeWindow: closeWindow,
		flapFlips:   flapFlips,
		flapWindow:  flapWindow,
		now:         time.Now,
	}
	if b, err := platformdb.Load(path); err == nil {
		var list []Episode
		if json.Unmarshal(b, &list) == nil {
			for i := range list {
				ep := list[i]
				s.episodes[ep.ID] = &ep
				if ep.Status != EpisodeStatusClosed {
					s.open[episodeKey(ep.TenantID, ep.Resource, ep.Signal, ep.State)] = ep.ID
				}
			}
		}
	}
	return s
}

// CloseWindow, FlapFlips and FlapWindow expose the fold knobs read-only (the
// episodes API discloses them so the UI can explain the lifecycle).
func (s *EpisodeStore) CloseWindow() time.Duration { return s.closeWindow }
func (s *EpisodeStore) FlapFlips() int             { return s.flapFlips }
func (s *EpisodeStore) FlapWindow() time.Duration  { return s.flapWindow }

// Now returns the store's current time (the injected clock in tests).
func (s *EpisodeStore) Now() time.Time { return s.now() }

// SetNowForTest injects a deterministic clock. Tests only.
func (s *EpisodeStore) SetNowForTest(now func() time.Time) { s.now = now }

// flushLocked persists the episode set, returning any failure.
//
// Callers deliberately do NOT fail the alert loop on a persist error — an
// unwritable disk must not stop alerts from being evaluated — but the error is
// now returned and LOGGED rather than discarded (F-78 class, §10 no silent
// failures). "Best effort" is a decision for the caller to make explicitly, not
// a reason for the store to hide the outcome.
func (s *EpisodeStore) flushLocked() error {
	list := make([]Episode, 0, len(s.episodes))
	for _, ep := range s.episodes {
		list = append(list, *ep)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// sweepLocked closes cleared episodes whose quiet gap exceeded the close
// window. Actively-firing episodes never close — only cleared ones age out.
func (s *EpisodeStore) sweepLocked(now time.Time) {
	for key, id := range s.open {
		ep, ok := s.episodes[id]
		if !ok {
			delete(s.open, key)
			continue
		}
		if ep.Status == EpisodeStatusCleared && now.Sub(ep.LastSeen) > s.closeWindow {
			ep.Status = EpisodeStatusClosed
			delete(s.open, key)
		}
	}
}

// evictLocked keeps a tenant's episode retention bounded: oldest CLOSED first,
// then oldest cleared; an actively-firing episode is never evicted.
func (s *EpisodeStore) evictLocked(tenant string) {
	var mine []*Episode
	for _, ep := range s.episodes {
		if ep.TenantID == tenant {
			mine = append(mine, ep)
		}
	}
	if len(mine) <= episodeMaxPerTenant {
		return
	}
	rank := func(status string) int {
		switch status {
		case EpisodeStatusClosed:
			return 0
		case EpisodeStatusCleared:
			return 1
		default:
			return 2
		}
	}
	sort.Slice(mine, func(i, j int) bool {
		if rank(mine[i].Status) != rank(mine[j].Status) {
			return rank(mine[i].Status) < rank(mine[j].Status)
		}
		return mine[i].LastSeen.Before(mine[j].LastSeen)
	})
	for _, ep := range mine[:len(mine)-episodeMaxPerTenant] {
		if ep.Status == EpisodeStatusActive {
			break // never drop a firing episode
		}
		delete(s.episodes, ep.ID)
		delete(s.open, episodeKey(ep.TenantID, ep.Resource, ep.Signal, ep.State))
	}
}

// recordFlipLocked notes a state transition and re-evaluates flap status:
// >= flapFlips transitions inside flapWindow marks the episode flapping.
// The mark is sticky for the episode's life — a flap that calms down stays
// visible as "was flapping" until the episode closes.
func (s *EpisodeStore) recordFlipLocked(ep *Episode, now time.Time) {
	ep.FlipCount++
	ep.Flips = append(ep.Flips, now)
	if len(ep.Flips) > episodeMaxFlipsKept {
		ep.Flips = ep.Flips[len(ep.Flips)-episodeMaxFlipsKept:]
	}
	recent := 0
	for _, t := range ep.Flips {
		if now.Sub(t) <= s.flapWindow {
			recent++
		}
	}
	if recent >= s.flapFlips {
		ep.Flapping = true
	}
}

// Observe folds one engine transition into the episode set. firing=true is a
// newly-firing alert; firing=false a resolution. Tenant is derived by the
// caller from the alert's device — never from any payload.
func (s *EpisodeStore) Observe(tenant, resource, signal, state, summary string, firing bool) {
	now := s.now().UTC()
	key := episodeKey(tenant, resource, signal, state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	id, hasOpen := s.open[key]
	if firing {
		if hasOpen {
			ep := s.episodes[id]
			if ep.Status == EpisodeStatusCleared {
				s.recordFlipLocked(ep, now) // cleared → firing again
			}
			ep.Status = EpisodeStatusActive
			ep.Count++
			ep.LastSeen = now
			if summary != "" {
				ep.Summary = summary
			}
		} else {
			ep := &Episode{
				ID: episodeID(), TenantID: tenant, Resource: resource, Signal: signal,
				State: state, Summary: summary, Status: EpisodeStatusActive,
				FirstSeen: now, LastSeen: now, Count: 1,
			}
			s.episodes[ep.ID] = ep
			s.open[key] = ep.ID
			s.evictLocked(tenant)
		}
	} else {
		if !hasOpen {
			return // resolve for an episode we never saw fire — nothing to fold
		}
		ep := s.episodes[id]
		if ep.Status == EpisodeStatusActive {
			ep.Status = EpisodeStatusCleared
			ep.LastSeen = now
			s.recordFlipLocked(ep, now) // firing → cleared
		}
	}
	if err := s.flushLocked(); err != nil {
		applog.Error("alerts", "episode persist failed", map[string]any{"err": err.Error()})
	}
}

// Suppressed reports whether notifications for this fold key are currently
// paused (open episode muted, or snoozed into the future). A key with no open
// episode is never suppressed — a NEW episode starts with notifications on.
func (s *EpisodeStore) Suppressed(tenant, resource, signal, state string) bool {
	now := s.now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.open[episodeKey(tenant, resource, signal, state)]
	if !ok {
		return false
	}
	ep, ok := s.episodes[id]
	return ok && ep.suppressed(now)
}

// EpisodeQuery bounds a List.
type EpisodeQuery struct {
	Status string // "" | active | cleared | closed | open (active+cleared)
	Limit  int
}

// List returns the episodes visible to the (tenant, cross) principal, most
// recently seen first, capped with disclosure. Visibility mirrors /api/alerts:
// cross sees all; a scoped principal sees its own tenant's episodes plus
// device-less (platform/stack) ones.
func (s *EpisodeStore) List(tenant string, cross bool, q EpisodeQuery) (eps []Episode, total int, truncated bool) {
	now := s.now().UTC()
	s.mu.Lock()
	s.sweepLocked(now)
	out := make([]Episode, 0, len(s.episodes))
	for _, ep := range s.episodes {
		if !cross && !(sameTenant(ep.TenantID, tenant) || ep.Resource == "") {
			continue
		}
		switch q.Status {
		case "", "all":
		case "open":
			if ep.Status == EpisodeStatusClosed {
				continue
			}
		default:
			if ep.Status != q.Status {
				continue
			}
		}
		out = append(out, *ep)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	total = len(out)
	limit := q.Limit
	if limit <= 0 {
		limit = episodeDefaultLimit
	}
	if limit > episodeMaxQueryLimit {
		limit = episodeMaxQueryLimit
	}
	if len(out) > limit {
		out, truncated = out[:limit], true
	}
	return out, total, truncated
}

// Reachable reports whether id exists AND the principal may see it. Used to gate
// input validation behind the 404, so a cross-tenant probe can never learn an
// id exists by receiving a 400 (input rejected) instead of a 404 (id hidden) —
// CLAUDE.md §3a. Same scoping rule as Triage, so the two cannot disagree.
func (s *EpisodeStore) Reachable(id, tenant string, cross bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.episodes[id]
	return ok && (cross || sameTenant(ep.TenantID, tenant))
}

// Triage applies a mutation to an episode the principal OWNS. Default-closed:
// a cross-tenant id (including a platform episode for a scoped caller) returns
// ErrEpisodeNotFound so existence is never revealed.
func (s *EpisodeStore) Triage(id, tenant string, cross bool, apply func(*Episode) error) (Episode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.episodes[id]
	if !ok || !(cross || sameTenant(ep.TenantID, tenant)) {
		return Episode{}, ErrEpisodeNotFound
	}
	if err := apply(ep); err != nil {
		return Episode{}, err
	}
	if err := s.flushLocked(); err != nil {
		applog.Error("alerts", "episode persist failed", map[string]any{"err": err.Error()})
	}
	return *ep, nil
}
