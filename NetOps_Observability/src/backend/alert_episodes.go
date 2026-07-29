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
	"strconv"
	"strings"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
)

// The episode store moved to alerts/episodes.go (Phase-2 W1.3) — it lives with
// the Engine that feeds it via OnTransition/SuppressNotify. Aliases keep the
// handlers, adapters and tests below source-compatible; the env knobs are read
// here (entrypoint) and passed to the constructor.
type (
	AlertEpisode      = alerts.Episode
	EpisodeNote       = alerts.EpisodeNote
	episodeQuery      = alerts.EpisodeQuery
	alertEpisodeStore = alerts.EpisodeStore
)

const (
	episodeStatusActive   = alerts.EpisodeStatusActive
	episodeStatusCleared  = alerts.EpisodeStatusCleared
	episodeStatusClosed   = alerts.EpisodeStatusClosed
	episodeMaxNotes       = alerts.EpisodeMaxNotes
	episodeMaxNoteChars   = alerts.EpisodeMaxNoteChars
	episodeMaxSnoozeAhead = alerts.EpisodeMaxSnoozeAhead
)

var errEpisodeNotFound = alerts.ErrEpisodeNotFound

// newAlertEpisodeStore reads the fold knobs from the environment
// (ALERT_EPISODE_CLOSE_WINDOW / ALERT_EPISODE_FLAP_FLIPS /
// ALERT_EPISODE_FLAP_WINDOW; defaults 15m / 6 / 15m) and builds the store.
func newAlertEpisodeStore(path string) *alerts.EpisodeStore {
	return alerts.NewEpisodeStore(path,
		envDuration("ALERT_EPISODE_CLOSE_WINDOW", 15*time.Minute),
		envInt("ALERT_EPISODE_FLAP_FLIPS", 6),
		envDuration("ALERT_EPISODE_FLAP_WINDOW", 15*time.Minute))
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
		"close_window_seconds": int(s.alertEpisodes.CloseWindow().Seconds()),
		"flap_flips":           s.alertEpisodes.FlapFlips(),
		"flap_window_seconds":  int(s.alertEpisodes.FlapWindow().Seconds()),
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
	now := s.alertEpisodes.Now().UTC()

	// §3a: check existence+ownership BEFORE any action-specific input validation.
	// Otherwise a cross-tenant probe with a malformed value (e.g. a snooze past
	// the 7-day cap) receives a 400 that confirms the id exists, instead of the
	// 404 that hides it. The 404 must win over the 400. Triage re-checks under
	// its own lock, so this is a fast-fail gate, not the authority.
	if !s.alertEpisodes.Reachable(id, tenant, cross) {
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
