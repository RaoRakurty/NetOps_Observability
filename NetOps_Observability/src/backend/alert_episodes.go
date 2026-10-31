// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/platformdb"
	"netops/backend/maintenance"
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

// experienceRulePrefix marks the Digital Experience rules, whose alert identity
// is a TARGET rather than a device (dem_* series carry no `device` label).
const experienceRulePrefix = "Experience"

// nmsRulePrefix marks the NMS connector-health rules (NMSIntegrationDown,
// NMSIngestSilent, …). Their subject is an INTEGRATION — a tenant's connection
// to its own controller — not a device, so they carry no `device` label.
const nmsRulePrefix = "NMS"

// alertTenant is the owning tenant of an alert, as the episode store and the
// incident bridge record it. It is s.alertOwner — the SAME derivation the alert
// visibility chokepoint (alertVisibility) applies — so an episode can never be
// owned by one tenant while its alert is shown to another, or hidden from it.
func (s *server) alertTenant(a models.Alert) string {
	return s.alertOwner(a)
}

// alertOwner is the ONE owner derivation for an alert. "" means platform-owned
// (platform-only, §3a default-closed).
//
//   - device set → the device's tenant from discovery; an unknown device owns
//     nothing (as before).
//   - Experience* rules (S17) → alertOwnerLabel: their `tenant` label is written
//     by OUR prober from the catalogue row.
//   - NMS* rules (F2) → the (tenant_id, integration_id) label PAIR, believed ONLY
//     when that exact pair is an enabled integration in the NMS runtime's last
//     ListEnabled snapshot. A label alone is never an owner: a forged tenant_id,
//     an id enabled only in another tenant, a disabled or deleted integration,
//     or NMS switched off all resolve to "" (platform-only). Integration ids are
//     unique only per tenant, so the id is never matched without its tenant.
//   - everything else device-less → "" (the platform's own stack alerts).
//
// Both label exceptions are keyed on the RULE NAME, never on the mere presence
// of a label: the general rule "an alert's labels are telemetry, not an owner"
// still stands for every other rule.
func (s *server) alertOwner(a models.Alert) string {
	if a.DeviceID != "" {
		if d, ok := s.discovery.Get(a.DeviceID); ok {
			return deviceTenant(d)
		}
		return ""
	}
	if strings.HasPrefix(a.Rule, nmsRulePrefix) {
		return s.nmsAlertOwner(a)
	}
	return alertOwnerLabel(a)
}

// nmsAlertOwner resolves a device-less NMS connector alert to the tenant that
// owns the integration it names, or "" when the pair is not a live, enabled
// integration of that tenant. No store call: the snapshot is in memory.
func (s *server) nmsAlertOwner(a models.Alert) string {
	if s.nms == nil {
		return ""
	}
	tenant := strings.ToLower(strings.TrimSpace(a.Labels["tenant_id"]))
	id := strings.TrimSpace(a.Labels["integration_id"])
	if tenant == "" || id == "" || !s.nms.IsEnabled(tenant, id) {
		return ""
	}
	return tenant
}

// alertOwnerLabel is the S17 exception on its own, with no server behind it: the
// owning tenant of a DEVICE-LESS Experience alert, or "" when nothing owns it.
//
// It is one branch of s.alertOwner, and it is also the fallback of an
// alertVisibility built without a server (alertVisibility.ownerOf): there, every
// owner that needs server state — the NMS integration snapshot — resolves to ""
// (platform-only), which is the default-closed direction.
func alertOwnerLabel(a models.Alert) string {
	if a.DeviceID != "" || !strings.HasPrefix(a.Rule, experienceRulePrefix) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(a.Labels["tenant"]))
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
// for this firing (muted/snoozed episode, or an active maintenance window
// covering the alert's device/site/rule). Never affects the active set. The
// maintenance check runs FIRST and independently of the episode lookup: the
// episode store only suppresses an already-OPEN episode, but a brand-new
// firing inside a declared window must be quiet too (item 121).
func (s *server) alertNotifySuppressed(a models.Alert) bool {
	if s.maintenanceSuppressed(a) {
		return true
	}
	if s.alertEpisodes == nil {
		return false
	}
	return s.alertEpisodes.Suppressed(s.alertTenant(a), a.DeviceID, a.Rule, alertEpisodeState(a.Severity))
}

// episodeScope resolves WHO is reading the episode store, ONCE per request: the
// ordinary tenant scope PLUS the per-tenant operator-visibility restriction
// (Tenant.OperatorRestricted), both taken from the shared tenantVisibility
// chokepoint rather than re-derived here.
//
// The restriction has to reach the STORE rather than stop at this handler,
// because the store computes the episode `total` over the visible set before
// limiting. A handler-side filter would drop the rows and leave the count — and
// "this tenant has 47 open episodes" is exactly the fact the restriction exists
// to withhold. tenant_id is the right key: an episode's owner is derived from
// its device when the transition folds and is stored on the row.
func (s *server) episodeScope(c jwtClaims) alerts.EpisodeScope {
	v := s.tenantVisibilityFor(c)
	return alerts.EpisodeScope{Tenant: v.tenant, Cross: v.cross, Deny: v.deny, Hidden: v.hiddenTenantIDs()}
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
	eps, total, truncated := s.alertEpisodes.List(s.episodeScope(claims), q)
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
	scope := s.episodeScope(claims)
	actor := claims.Sub
	now := s.alertEpisodes.Now().UTC()

	// §3a: check existence+ownership BEFORE any action-specific input validation.
	// Otherwise a cross-tenant probe with a malformed value (e.g. a snooze past
	// the 7-day cap) receives a 400 that confirms the id exists, instead of the
	// 404 that hides it. The 404 must win over the 400. Triage re-checks under
	// its own lock, so this is a fast-fail gate, not the authority.
	if !s.alertEpisodes.Reachable(id, scope) {
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

	ep, err := s.alertEpisodes.Triage(id, scope, apply)
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

// ── maintenance windows (item 121: the #53 remnant) ──────────────────────────
//
// Declared planned-work periods. A covering window pauses alert NOTIFICATIONS
// only — same honesty rule as mute/snooze — and stamps timeintel snapshots so
// MTBF / chronic-offender math separates planned from unplanned downtime.
// Store: maintenance/ (file backend tenant-filtered in-store, PG FORCE-RLS via
// migration 0031). Routes:
//
//	GET|POST          /api/alerts/maintenance-windows
//	GET|PUT|DELETE    /api/alerts/maintenance-windows/{id}

// newMaintenanceWindowStore selects pg under the Postgres backend, else file.
func newMaintenanceWindowStore() maintenance.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return maintenance.NewPGStore(ps.DB())
	}
	return maintenance.NewFileStore(envOr("MAINTENANCE_WINDOWS_FILE", "/data/maintenance_windows.json"))
}

// maintenanceCoveredAt reports whether a covering window exists for the triple
// at the given instant. Fail-OPEN on store errors (noisy beats silently dark —
// a broken store must never hide real alerts), but the error is logged (§10).
func (s *server) maintenanceCoveredAt(tenant, device, site, rule string, at time.Time) bool {
	if s.maintWindows == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, covered, err := s.maintWindows.Covering(ctx, tenant, device, site, rule, at)
	if err != nil {
		log.Printf("maintenance window lookup: %v", err)
		return false
	}
	return covered
}

// maintTriple is one (device id, tenant, site) lookup for bulk window checks.
type maintTriple struct{ id, tenant, site string }

// maintenanceCoveredIDs reports which of the given devices are inside an
// active maintenance window right now — the topology projections render those
// as the calm HealthMaintenance state (item 121). One window read per tenant;
// a failed read leaves that tenant unstamped (fail toward the ordinary state,
// §10-logged). Rules-scoped windows never match here (rule = ""), mirroring
// the timeintel backfill's conservative semantics.
func (s *server) maintenanceCoveredIDs(items []maintTriple) map[string]bool {
	if s.maintWindows == nil || len(items) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	winsByTenant := map[string][]maintenance.Window{}
	out := map[string]bool{}
	for _, it := range items {
		wins, ok := winsByTenant[it.tenant]
		if !ok {
			var err error
			wins, err = s.maintWindows.List(ctx, it.tenant, false)
			if err != nil {
				log.Printf("maintenance window read (topology): %v", err)
				wins = nil
			}
			winsByTenant[it.tenant] = wins
		}
		for i := range wins {
			if wins[i].Covers(now, it.id, it.site, "") {
				out[it.id] = true
				break
			}
		}
	}
	return out
}

// maintenanceCoveredDevices is maintenanceCoveredIDs over the live inventory
// (site resolved through the operator device→site binding, like suppression).
func (s *server) maintenanceCoveredDevices(devs []models.Device) map[string]bool {
	if s.maintWindows == nil || len(devs) == 0 {
		return nil
	}
	items := make([]maintTriple, 0, len(devs))
	for _, d := range devs {
		tenant := deviceTenant(d)
		site := ""
		if s.deviceSites != nil {
			if b, ok := s.deviceSites.Get(tenant, false, d.ID); ok {
				site = b.Site
			}
		}
		items = append(items, maintTriple{id: d.ID, tenant: tenant, site: site})
	}
	return s.maintenanceCoveredIDs(items)
}

// maintenanceSuppressed derives the alert's tenant/site the same way the
// episode fold does and asks the window store about NOW.
func (s *server) maintenanceSuppressed(a models.Alert) bool {
	if s.maintWindows == nil {
		return false
	}
	tenant := s.alertTenant(a)
	site := ""
	if a.DeviceID != "" && s.deviceSites != nil {
		if b, ok := s.deviceSites.Get(tenant, false, a.DeviceID); ok {
			site = b.Site
		}
	}
	return s.maintenanceCoveredAt(tenant, a.DeviceID, site, a.Rule, time.Now().UTC())
}

// decodeMaintenanceWindow reads and validates an operator payload. `enabled`
// defaults to TRUE when omitted (a freshly-declared window that silently did
// nothing would be the worst failure mode).
func decodeMaintenanceWindow(w http.ResponseWriter, r *http.Request) (maintenance.Window, bool) {
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return maintenance.Window{}, false
	}
	var in maintenance.Window
	if err := json.Unmarshal(raw, &in); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return maintenance.Window{}, false
	}
	var probe struct {
		Enabled *bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &probe) == nil && probe.Enabled == nil {
		in.Enabled = true
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return maintenance.Window{}, false
	}
	return in, true
}

// visibleMaintenanceWindows reads the declared planned-work windows through the
// SAME resolved rule the device registry and the declared sites are read
// through, so the list and the `count` beside it can never disagree about what
// the caller may see.
//
// A maintenance window is when a customer's network is deliberately down and who
// is touching it: it names device ids, site slugs, rule names, a description and
// a schedule. That is the same class of disclosure as the site list and the
// fleet the owner already ruled is per-tenant, so a restricted tenant's windows
// are not part of the platform operator's estate either.
//
// The count is computed HERE, over the filtered list, and that is enough — the
// store returns whole rows with no bound of its own, so unlike the episode list
// (whose total is computed inside the store, before its limit) there is no count
// a handler-side filter could leave behind. Checked, not assumed:
// maintenance.Store.List takes no limit and returns every row of the scope.
func (s *server) visibleMaintenanceWindows(ctx context.Context, c jwtClaims) ([]maintenance.Window, error) {
	v := s.tenantVisibilityFor(c)
	if v.deny {
		// The operator scoped INTO a restricted tenant: nothing, not an error.
		return []maintenance.Window{}, nil
	}
	all, err := s.maintWindows.List(ctx, v.tenant, v.cross)
	if err != nil {
		return nil, err
	}
	if len(v.hiddenTenants) == 0 {
		return all, nil
	}
	out := make([]maintenance.Window, 0, len(all))
	for _, win := range all {
		if v.hides(win.TenantID) {
			continue
		}
		out = append(out, win)
	}
	return out, nil
}

// maintenanceWindowRestricted reports whether the operator-visibility
// restriction hides the window with this id from the caller — the by-id gate for
// every method, read and write alike.
//
// The WRITE half is deliberate and mirrors the episode store's `owns`: a window
// platform staff may not read is not one they may overwrite or delete either,
// and a 200 from PUT/DELETE on an id the GET refuses would confirm the id exists
// just as loudly as a 403. The callers answer 404.
//
// It costs an extra store read ONLY when something is actually hidden from this
// caller — every ordinary request (no restricted tenant, a tenant's own users,
// an operator with nothing hidden) short-circuits on the empty set.
func (s *server) maintenanceWindowRestricted(ctx context.Context, v tenantVisibility, id string) (bool, error) {
	if len(v.hiddenTenants) == 0 {
		return false, nil
	}
	win, found, err := s.maintWindows.Get(ctx, v.tenant, v.cross, id)
	if err != nil {
		return false, err
	}
	return found && v.hides(win.TenantID), nil
}

func (s *server) handleMaintenanceWindows(w http.ResponseWriter, r *http.Request) {
	if s.maintWindows == nil {
		writeError(w, http.StatusNotImplemented, errors.New("maintenance window store unavailable"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		out, err := s.visibleMaintenanceWindows(r.Context(), claims)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"windows": out, "count": len(out)})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		in, ok := decodeMaintenanceWindow(w, r)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // §3a.2: owner from the token, never the body
		}
		in.CreatedBy = claims.Sub
		out, err := s.maintWindows.Create(r.Context(), tenant, cross, in)
		if errors.Is(err, maintenance.ErrLimit) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleMaintenanceWindowByID(w http.ResponseWriter, r *http.Request) {
	if s.maintWindows == nil {
		writeError(w, http.StatusNotImplemented, errors.New("maintenance window store unavailable"))
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/alerts/maintenance-windows/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid window id"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
		if !ok {
			return
		}
		v := s.tenantVisibilityFor(claims)
		if v.deny {
			http.NotFound(w, r) // scoped INTO a restricted tenant: nothing exists here
			return
		}
		win, found, err := s.maintWindows.Get(r.Context(), v.tenant, v.cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		// The restriction is asked BEFORE the found/not-found answer is written,
		// because the store's tenancy rule returns everything to a cross-tenant
		// caller. A hidden window reads as absent — never 403, which would
		// confirm the id.
		if !found || v.hides(win.TenantID) {
			http.NotFound(w, r) // cross-tenant id indistinguishable from absent
			return
		}
		writeJSON(w, http.StatusOK, win)
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		v := s.tenantVisibilityFor(claims)
		if v.deny {
			http.NotFound(w, r)
			return
		}
		in, ok := decodeMaintenanceWindow(w, r)
		if !ok {
			return
		}
		// §3a.1: a window platform staff may not read is not one they may
		// overwrite. Checked BEFORE the write, so the refusal is not a rollback.
		hidden, err := s.maintenanceWindowRestricted(r.Context(), v, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if hidden {
			http.NotFound(w, r)
			return
		}
		out, found, err := s.maintWindows.Update(r.Context(), v.tenant, v.cross, id, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "alerts", LevelWrite)
		if !ok {
			return
		}
		v := s.tenantVisibilityFor(claims)
		if v.deny {
			http.NotFound(w, r)
			return
		}
		hidden, err := s.maintenanceWindowRestricted(r.Context(), v, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if hidden {
			http.NotFound(w, r) // and the planned work stays declared
			return
		}
		found, err := s.maintWindows.Delete(r.Context(), v.tenant, v.cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}
