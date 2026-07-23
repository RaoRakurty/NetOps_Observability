package main

// alert_episodes.go — alert EPISODE grouping + triage (cloud-platform backlog
// Wave 2 #6, product-review rev #7 + missing #4/#5).
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
// Triage: ack / assign / mute / snooze / notes, actor always stamped from the
// authenticated principal. Mute/snooze suppress outbound NOTIFICATIONS only
// (Engine.SuppressNotify) — the episode row stays visible with its suppressed
// state shown honestly. Every triage action lands in the audit trail.
//
// Tenancy (§3a): an episode's tenant is derived from its device at fold time
// (device-less/stack episodes are platform-owned, tenant ""). Reads mirror the
// /api/alerts rule — a scoped principal sees its own tenant's episodes plus
// device-less ones; writes are strictly own-tenant (cross-tenant id → 404,
// platform episodes are platform-owner-only to triage).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
)

const (
	episodeStatusActive  = "active"
	episodeStatusCleared = "cleared"
	episodeStatusClosed  = "closed"

	episodeDefaultCloseWindow = 15 * time.Minute
	episodeDefaultFlapFlips   = 6
	episodeDefaultFlapWindow  = 15 * time.Minute

	episodeMaxPerTenant   = 500  // per-tenant retention cap; oldest closed evicted first
	episodeMaxNotes       = 50   // notes per episode
	episodeMaxNoteChars   = 2000 // characters per note
	episodeMaxFlipsKept   = 64   // flip-timestamp ring (flap detection only needs the window)
	episodeDefaultLimit   = 200  // list default
	episodeMaxQueryLimit  = 500  // list hard cap (disclosed via `truncated`)
	episodeMaxSnoozeAhead = 7 * 24 * time.Hour
)

// EpisodeNote is one triage annotation (who/when/what).
type EpisodeNote struct {
	At   time.Time `json:"at"`
	By   string    `json:"by"`
	Text string    `json:"text"`
}

// AlertEpisode is the folded view of repeated firings of one
// (tenant, resource, signal, state) plus its triage state.
type AlertEpisode struct {
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
func (ep *AlertEpisode) suppressed(now time.Time) bool {
	return ep.Muted || (ep.SnoozedUntil != nil && now.Before(*ep.SnoozedUntil))
}

func episodeKey(tenant, resource, signal, state string) string {
	return tenant + "\x1f" + resource + "\x1f" + signal + "\x1f" + state
}

// alertEpisodeStore folds alert transitions into episodes. File-backed like the
// rest of the alerts-adjacent state (bounded, tenant-scoped in-store); the
// engine's transitions are tick-grained, so the write rate is low.
type alertEpisodeStore struct {
	mu       sync.RWMutex
	path     string
	episodes map[string]*AlertEpisode // id → episode
	open     map[string]string        // fold key → id of the NOT-closed episode

	closeWindow time.Duration
	flapFlips   int
	flapWindow  time.Duration

	now func() time.Time // test seam
}

// newAlertEpisodeStore loads persisted episodes and reads the fold knobs from
// the environment: ALERT_EPISODE_CLOSE_WINDOW (quiet gap that closes a cleared
// episode), ALERT_EPISODE_FLAP_FLIPS / ALERT_EPISODE_FLAP_WINDOW (N flips in M
// marks the episode flapping). Defaults: 15m / 6 / 15m.
func newAlertEpisodeStore(path string) *alertEpisodeStore {
	s := &alertEpisodeStore{
		path:        path,
		episodes:    map[string]*AlertEpisode{},
		open:        map[string]string{},
		closeWindow: envDuration("ALERT_EPISODE_CLOSE_WINDOW", episodeDefaultCloseWindow),
		flapFlips:   envInt("ALERT_EPISODE_FLAP_FLIPS", episodeDefaultFlapFlips),
		flapWindow:  envDuration("ALERT_EPISODE_FLAP_WINDOW", episodeDefaultFlapWindow),
		now:         time.Now,
	}
	if s.flapFlips < 2 {
		s.flapFlips = 2 // below 2 every clear would count as a flap
	}
	if b, err := kvLoad(path); err == nil {
		var list []AlertEpisode
		if json.Unmarshal(b, &list) == nil {
			for i := range list {
				ep := list[i]
				s.episodes[ep.ID] = &ep
				if ep.Status != episodeStatusClosed {
					s.open[episodeKey(ep.TenantID, ep.Resource, ep.Signal, ep.State)] = ep.ID
				}
			}
		}
	}
	return s
}

// flushLocked persists the episode set, returning any failure.
//
// Callers deliberately do NOT fail the alert loop on a persist error — an
// unwritable disk must not stop alerts from being evaluated — but the error is
// now returned and LOGGED rather than discarded (F-78 class, §10 no silent
// failures). "Best effort" is a decision for the caller to make explicitly, not
// a reason for the store to hide the outcome.
func (s *alertEpisodeStore) flushLocked() error {
	list := make([]AlertEpisode, 0, len(s.episodes))
	for _, ep := range s.episodes {
		list = append(list, *ep)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// sweepLocked closes cleared episodes whose quiet gap exceeded the close
// window. Actively-firing episodes never close — only cleared ones age out.
func (s *alertEpisodeStore) sweepLocked(now time.Time) {
	for key, id := range s.open {
		ep, ok := s.episodes[id]
		if !ok {
			delete(s.open, key)
			continue
		}
		if ep.Status == episodeStatusCleared && now.Sub(ep.LastSeen) > s.closeWindow {
			ep.Status = episodeStatusClosed
			delete(s.open, key)
		}
	}
}

// evictLocked keeps a tenant's episode retention bounded: oldest CLOSED first,
// then oldest cleared; an actively-firing episode is never evicted.
func (s *alertEpisodeStore) evictLocked(tenant string) {
	var mine []*AlertEpisode
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
		case episodeStatusClosed:
			return 0
		case episodeStatusCleared:
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
		if ep.Status == episodeStatusActive {
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
func (s *alertEpisodeStore) recordFlipLocked(ep *AlertEpisode, now time.Time) {
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
func (s *alertEpisodeStore) Observe(tenant, resource, signal, state, summary string, firing bool) {
	now := s.now().UTC()
	key := episodeKey(tenant, resource, signal, state)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)

	id, hasOpen := s.open[key]
	if firing {
		if hasOpen {
			ep := s.episodes[id]
			if ep.Status == episodeStatusCleared {
				s.recordFlipLocked(ep, now) // cleared → firing again
			}
			ep.Status = episodeStatusActive
			ep.Count++
			ep.LastSeen = now
			if summary != "" {
				ep.Summary = summary
			}
		} else {
			ep := &AlertEpisode{
				ID: randHex(8), TenantID: tenant, Resource: resource, Signal: signal,
				State: state, Summary: summary, Status: episodeStatusActive,
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
		if ep.Status == episodeStatusActive {
			ep.Status = episodeStatusCleared
			ep.LastSeen = now
			s.recordFlipLocked(ep, now) // firing → cleared
		}
	}
	if err := s.flushLocked(); err != nil {
		logError("alerts", "episode persist failed", map[string]any{"err": err.Error()})
	}
}

// Suppressed reports whether notifications for this fold key are currently
// paused (open episode muted, or snoozed into the future). A key with no open
// episode is never suppressed — a NEW episode starts with notifications on.
func (s *alertEpisodeStore) Suppressed(tenant, resource, signal, state string) bool {
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

// episodeQuery bounds a List.
type episodeQuery struct {
	Status string // "" | active | cleared | closed | open (active+cleared)
	Limit  int
}

// List returns the episodes visible to the (tenant, cross) principal, most
// recently seen first, capped with disclosure. Visibility mirrors /api/alerts:
// cross sees all; a scoped principal sees its own tenant's episodes plus
// device-less (platform/stack) ones.
func (s *alertEpisodeStore) List(tenant string, cross bool, q episodeQuery) (eps []AlertEpisode, total int, truncated bool) {
	now := s.now().UTC()
	s.mu.Lock()
	s.sweepLocked(now)
	out := make([]AlertEpisode, 0, len(s.episodes))
	for _, ep := range s.episodes {
		if !cross && !(sameTenantStrict(ep.TenantID, tenant) || ep.Resource == "") {
			continue
		}
		switch q.Status {
		case "", "all":
		case "open":
			if ep.Status == episodeStatusClosed {
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

var errEpisodeNotFound = errors.New("episode not found")

// Triage applies a mutation to an episode the principal OWNS. Default-closed:
// a cross-tenant id (including a platform episode for a scoped caller) returns
// errEpisodeNotFound so existence is never revealed.
// reachable reports whether id exists AND the principal may see it. Used to gate
// input validation behind the 404, so a cross-tenant probe can never learn an
// id exists by receiving a 400 (input rejected) instead of a 404 (id hidden) —
// CLAUDE.md §3a. Same scoping rule as Triage, so the two cannot disagree.
func (s *alertEpisodeStore) reachable(id, tenant string, cross bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.episodes[id]
	return ok && (cross || sameTenantStrict(ep.TenantID, tenant))
}

func (s *alertEpisodeStore) Triage(id, tenant string, cross bool, apply func(*AlertEpisode) error) (AlertEpisode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ep, ok := s.episodes[id]
	if !ok || !(cross || sameTenantStrict(ep.TenantID, tenant)) {
		return AlertEpisode{}, errEpisodeNotFound
	}
	if err := apply(ep); err != nil {
		return AlertEpisode{}, err
	}
	if err := s.flushLocked(); err != nil {
		logError("alerts", "episode persist failed", map[string]any{"err": err.Error()})
	}
	return *ep, nil
}

// ── server adapters (engine → episodes) ──────────────────────────────────────

// alertTenant derives the owning tenant of an alert from its device. Device-less
// (stack-level) alerts and alerts on unknown devices are platform-owned ("").
func (s *server) alertTenant(a models.Alert) string {
	if a.DeviceID == "" {
		return ""
	}
	if d, ok := s.discovery.Get(a.DeviceID); ok {
		return deviceTenant(d)
	}
	return ""
}

// alertEpisodeState normalizes the severity into the episode's state facet.
func alertEpisodeState(severity string) string {
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev == "" {
		return "firing"
	}
	return sev
}

// observeAlertTransition is Engine.OnTransition: fold a fire/resolve into episodes.
func (s *server) observeAlertTransition(a models.Alert, firing bool) {
	if s.alertEpisodes == nil {
		return
	}
	s.alertEpisodes.Observe(s.alertTenant(a), a.DeviceID, a.Rule, alertEpisodeState(a.Severity), a.Summary, firing)
}

// alertNotifySuppressed is Engine.SuppressNotify: true pauses the notification
// for this firing (muted/snoozed episode). Never affects the active set.
func (s *server) alertNotifySuppressed(a models.Alert) bool {
	if s.alertEpisodes == nil {
		return false
	}
	return s.alertEpisodes.Suppressed(s.alertTenant(a), a.DeviceID, a.Rule, alertEpisodeState(a.Severity))
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// handleAlertEpisodes serves GET /api/alerts/episodes — the tenant-scoped
// episode list. Same authn posture as GET /api/alerts (any authenticated
// principal, scoped by tenant), bounded with an explicit truncation disclosure.
func (s *server) handleAlertEpisodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.alertEpisodes == nil {
		writeJSON(w, http.StatusOK, map[string]any{"episodes": []AlertEpisode{}, "total": 0, "truncated": false})
		return
	}
	claims, _ := userFrom(r.Context())
	tenant, cross := principalTenant(claims)
	q := episodeQuery{Status: strings.TrimSpace(r.URL.Query().Get("status"))}
	switch q.Status {
	case "", "all", "open", episodeStatusActive, episodeStatusCleared, episodeStatusClosed:
	default:
		writeError(w, http.StatusBadRequest, errors.New("status must be one of open, active, cleared, closed, all"))
		return
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, errors.New("limit must be a number"))
			return
		}
		q.Limit = n
	}
	eps, total, truncated := s.alertEpisodes.List(tenant, cross, q)
	writeJSON(w, http.StatusOK, map[string]any{
		"episodes":             eps,
		"total":                total,
		"truncated":            truncated,
		"close_window_seconds": int(s.alertEpisodes.closeWindow.Seconds()),
		"flap_flips":           s.alertEpisodes.flapFlips,
		"flap_window_seconds":  int(s.alertEpisodes.flapWindow.Seconds()),
	})
}

// assigneePattern bounds an assignee handle: local usernames or email-shaped
// federated subjects. Zero-trust on the payload — anything else is rejected.
var assigneePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$`)

// handleAlertEpisodeAction serves POST /api/alerts/episodes/{id}/{action} with
// action ∈ ack | assign | mute | snooze | notes. Requires alerts:write; the
// actor is ALWAYS the authenticated principal; cross-tenant ids → 404. Each
// action lands in the audit trail with who/when/what detail.
func (s *server) handleAlertEpisodeAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
	if !ok {
		return
	}
	if s.alertEpisodes == nil {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/alerts/episodes/")
	id, action, ok := strings.Cut(rest, "/")
	if !ok || id == "" || strings.Contains(action, "/") {
		http.NotFound(w, r)
		return
	}
	tenant, cross := principalTenant(claims)
	actor := claims.Sub
	now := s.alertEpisodes.now().UTC()

	// §3a: check existence+ownership BEFORE any action-specific input validation.
	// Otherwise a cross-tenant probe with a malformed value (e.g. a snooze past
	// the 7-day cap) receives a 400 that confirms the id exists, instead of the
	// 404 that hides it. The 404 must win over the 400. Triage re-checks under
	// its own lock, so this is a fast-fail gate, not the authority.
	if !s.alertEpisodes.reachable(id, tenant, cross) {
		http.NotFound(w, r)
		return
	}

	var body struct {
		Acknowledged *bool  `json:"acknowledged"`
		Assignee     string `json:"assignee"`
		Muted        *bool  `json:"muted"`
		Until        string `json:"until"`
		Text         string `json:"text"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}

	detail := map[string]any{"action": action}
	var apply func(*AlertEpisode) error
	switch action {
	case "ack":
		acked := body.Acknowledged == nil || *body.Acknowledged // default: acknowledge
		detail["acknowledged"] = acked
		apply = func(ep *AlertEpisode) error {
			if acked {
				ep.AcknowledgedBy, ep.AcknowledgedAt = actor, &now
			} else {
				ep.AcknowledgedBy, ep.AcknowledgedAt = "", nil
			}
			return nil
		}
	case "assign":
		assignee := strings.TrimSpace(body.Assignee)
		if assignee != "" && !assigneePattern.MatchString(assignee) {
			writeError(w, http.StatusBadRequest, errors.New("assignee must be a username (letters, digits, . _ @ + -, max 64)"))
			return
		}
		detail["assignee"] = assignee
		apply = func(ep *AlertEpisode) error {
			ep.AssignedTo = assignee
			if assignee == "" {
				ep.AssignedBy = ""
			} else {
				ep.AssignedBy = actor
			}
			return nil
		}
	case "mute":
		muted := body.Muted == nil || *body.Muted // default: mute
		detail["muted"] = muted
		apply = func(ep *AlertEpisode) error {
			ep.Muted = muted
			if muted {
				ep.MutedBy = actor
			} else {
				ep.MutedBy = ""
			}
			return nil
		}
	case "snooze":
		var until *time.Time
		if strings.TrimSpace(body.Until) != "" {
			t, err := time.Parse(time.RFC3339, body.Until)
			if err != nil {
				writeError(w, http.StatusBadRequest, errors.New("until must be an RFC3339 timestamp"))
				return
			}
			t = t.UTC()
			if !t.After(now) {
				writeError(w, http.StatusBadRequest, errors.New("snooze must end in the future"))
				return
			}
			if t.After(now.Add(episodeMaxSnoozeAhead)) {
				writeError(w, http.StatusBadRequest, errors.New("snooze is capped at 7 days"))
				return
			}
			until = &t
			detail["until"] = t.Format(time.RFC3339)
		} else {
			detail["until"] = "" // cleared
		}
		apply = func(ep *AlertEpisode) error {
			ep.SnoozedUntil = until
			if until == nil {
				ep.SnoozedBy = ""
			} else {
				ep.SnoozedBy = actor
			}
			return nil
		}
	case "notes":
		text := strings.TrimSpace(body.Text)
		if text == "" {
			writeError(w, http.StatusBadRequest, errors.New("note text is required"))
			return
		}
		if len(text) > episodeMaxNoteChars {
			writeError(w, http.StatusBadRequest, fmt.Errorf("note is capped at %d characters", episodeMaxNoteChars))
			return
		}
		detail["note_chars"] = len(text) // length only — note text stays out of logs
		apply = func(ep *AlertEpisode) error {
			if len(ep.Notes) >= episodeMaxNotes {
				return fmt.Errorf("this episode already has the maximum of %d notes", episodeMaxNotes)
			}
			ep.Notes = append(ep.Notes, EpisodeNote{At: now, By: actor, Text: text})
			return nil
		}
	default:
		http.NotFound(w, r)
		return
	}

	ep, err := s.alertEpisodes.Triage(id, tenant, cross, apply)
	if errors.Is(err, errEpisodeNotFound) {
		http.NotFound(w, r) // never reveal another tenant's episode ids
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.recordEpisodeTriage(r, claims, ep, detail)
	writeJSON(w, http.StatusOK, ep)
}

// recordEpisodeTriage writes the triage action into the immutable audit trail
// with who/when/what detail (the generic mutation envelope alone lacks the
// action semantics). Note TEXT is never logged — only its length.
func (s *server) recordEpisodeTriage(r *http.Request, claims jwtClaims, ep AlertEpisode, detail map[string]any) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	detail["episode"] = ep.ID
	detail["signal"] = ep.Signal
	detail["state"] = ep.State
	if ep.Resource != "" {
		detail["resource"] = ep.Resource
	}
	s.audit.Record(AuditEvent{
		Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: "TRIAGE", Path: "/api/alerts/episodes/" + ep.ID, Status: http.StatusOK,
		Decision: "allow", Remote: auditClientIP(r), Detail: detail,
	})
}
