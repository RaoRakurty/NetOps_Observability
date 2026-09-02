package igpmon

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/httppage"
)

// http.go — the read surface, under /api/protocols/{ospf|isis}/*.
//
// Every handler follows the same order, and the order IS the isolation
// guarantee (the pcap/configstore precedent):
//
//  1. AUTHORIZE at the read gate.
//  2. REFUSE unknown query parameters and bound every value that is accepted —
//     a caller who asks for 10 000 rows learns that they cannot have them
//     instead of receiving 200 rows with a 200 status.
//  3. RESOLVE ?device= through the principal-scoped inventory. Another
//     tenant's id and a nonexistent id answer the SAME 404.
//  4. READ events at the caller's ClickHouse tenant_scope (row policies) and
//     metrics with the caller's extra_filters[] device boundary.
//  5. REPORT coverage honestly: an absent source is null + a note, never zero.
//
// The tenant is never read from a query string or a body.

// Bounds (§9: every read has a ceiling).
const (
	defaultWindow = 24 * time.Hour
	minWindow     = time.Minute
	maxWindow     = 7 * 24 * time.Hour

	defaultLimit = 200
	maxLimit     = 1000

	defaultSummaryLimit = 100
	maxSummaryLimit     = 500

	// maxSummaryEvents bounds the event scan a roll-up is computed from. The
	// response says when the cap was hit, so a partial roll-up is never
	// presented as a complete one.
	maxSummaryEvents = 2000

	// maxTimeline bounds the per-adjacency timeline in a response body.
	maxTimeline = 200
)

// Handler returns the single dispatcher for the /api/protocols/{proto}/{op}
// routes. main.go registers each concrete path against it, so every route
// stays individually visible to the route-isolation ledger guard.
func (a *API) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a == nil {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
			return
		}
		const prefix = "/api/protocols/"
		rest := strings.TrimPrefix(r.URL.Path, prefix)
		if rest == r.URL.Path {
			http.NotFound(w, r)
			return
		}
		protoTok, op, found := strings.Cut(rest, "/")
		if !found || strings.Contains(op, "/") {
			http.NotFound(w, r)
			return
		}
		proto, ok := ProtoFrom(protoTok)
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch op {
		case "adjacencies":
			a.handleAdjacencies(w, r, proto)
		case "summary":
			a.handleSummary(w, r, proto)
		case "health":
			a.handleHealth(w, r, proto)
		default:
			http.NotFound(w, r)
		}
	}
}

// ── parameter parsing (fail closed) ─────────────────────────────────────────

// parseWindow reads ?since= as a duration ("90m", "24h", "7d") or as a plain
// number of seconds. A malformed or out-of-range value is an ERROR, never a
// silent fallback to the default: a caller who asked for 30 days must be told
// they got 7, not handed 7 with a 200.
func parseWindow(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultWindow, nil
	}
	var d time.Duration
	switch {
	case strings.HasSuffix(s, "d"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("since: %q is not a duration", raw)
		}
		d = time.Duration(n) * 24 * time.Hour
	default:
		if n, err := strconv.Atoi(s); err == nil {
			d = time.Duration(n) * time.Second
		} else {
			p, perr := time.ParseDuration(s)
			if perr != nil {
				return 0, fmt.Errorf("since: %q is not a duration", raw)
			}
			d = p
		}
	}
	if d < minWindow || d > maxWindow {
		return 0, fmt.Errorf("since: %s is outside the accepted range %s..%s", d, minWindow, maxWindow)
	}
	return d, nil
}

// parseLimit reads ?limit= and fails closed on anything out of range.
func parseLimit(raw string, def, max int) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("limit: %q is not an integer", raw)
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("limit: %d is outside the accepted range 1..%d", n, max)
	}
	return n, nil
}

// resolveDevice authorizes ?device=. It returns the identity set to filter on
// (id AND name, because the two collector lanes label series with different
// ones) and false when the handler has already answered 404.
//
// §3a rule 1: a device owned by another tenant and a device that does not exist
// produce the SAME response, so existence is never revealed.
func (a *API) resolveDevice(w http.ResponseWriter, r *http.Request, p Principal, raw string) (dev Device, ids []string, ok bool) {
	id := chToken(raw)
	if id == "" {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("device: required"))
		return Device{}, nil, false
	}
	d, found := a.deps.LookupDevice(id)
	if !found || !a.deps.CanSee(d, p) {
		http.NotFound(w, r)
		return Device{}, nil, false
	}
	ids = append(ids, d.ID)
	if d.Name != "" && d.Name != d.ID {
		ids = append(ids, d.Name)
	}
	return d, ids, true
}

// sourceLabel names which evidence classes actually backed the answer.
func sourceLabel(c Coverage) string {
	switch {
	case c.Events && c.LiveSeries:
		return "events+live_series"
	case c.Events:
		return "events"
	case c.LiveSeries:
		return "live_series"
	default:
		return "none"
	}
}

// ── GET /api/protocols/{proto}/adjacencies ──────────────────────────────────

func (a *API) handleAdjacencies(w http.ResponseWriter, r *http.Request, proto Proto) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "device", "since", "limit", "cursor"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("since"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"), defaultLimit, maxLimit)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var curMS int64
	var curID string
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		ms, sid, cok := decodeCursor(raw)
		if !cok {
			a.deps.WriteError(w, http.StatusBadRequest, errors.New("cursor: malformed"))
			return
		}
		curMS, curID = ms, sid
	}

	var deviceIDs []string
	deviceParam := strings.TrimSpace(r.URL.Query().Get("device"))
	if deviceParam != "" {
		if _, ids, dok := a.resolveDevice(w, r, p, deviceParam); dok {
			deviceIDs = ids
		} else {
			return
		}
	}

	now := a.deps.Now().UTC()
	since := now.Add(-window)
	ctx := r.Context()

	var notes []string
	cov := Coverage{}

	events, err := a.fetchEvents(ctx, a.deps.Scope(r), EventQuery{
		Kind:     proto.Kind(),
		Devices:  deviceIDs,
		SinceMS:  since.UnixMilli(),
		CursorMS: curMS,
		CursorID: curID,
		Limit:    limit,
	})
	switch {
	case err != nil:
		notes = append(notes, "adjacency-change events unavailable: the correlation store could not be queried")
	default:
		cov.Events = true
	}

	truncated := false
	next := ""
	if len(events) > limit {
		events = events[:limit]
		truncated = true
	}
	if truncated && len(events) > 0 {
		last := events[len(events)-1]
		next = encodeCursor(last.TSMillis, last.SignalID)
	}

	live := a.fetchLive(ctx, r, p, proto, deviceIDs)
	cov.LiveSeries = live.available
	if !live.available {
		notes = append(notes, live.note)
	}
	adv := a.fetchAdvanced(ctx, r, p, proto, deviceIDs)
	cov.applyAdvanced(adv)
	notes = append(notes, adv.notes()...)

	a.deps.Metrics.Query(proto, "adjacencies")
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"protocol":       string(proto),
		"device":         deviceParam,
		"window_seconds": int(window.Seconds()),
		"since":          since.Format(time.RFC3339),
		"now":            now.Format(time.RFC3339),
		"adjacencies":    MergeAdjacencies(live.rows, events, adv.timers.byAdj, maxTimeline),
		"event_count":    len(events),
		"lsdb":           adv.lsdbBlock(proto),
		"areas":          adv.areasBlock(),
		"spf_runs":       adv.spfBlock(proto),
		"timers":         adv.timersBlock(proto),
		"coverage":       cov,
		"source":         sourceLabel(cov),
		"notes":          notes,
		"limit":          limit,
		"truncated":      truncated,
		"next_cursor":    next,
	})
}

// ── GET /api/protocols/{proto}/summary ──────────────────────────────────────

func (a *API) handleSummary(w http.ResponseWriter, r *http.Request, proto Proto) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "since", "limit"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("since"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := parseLimit(r.URL.Query().Get("limit"), defaultSummaryLimit, maxSummaryLimit)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}

	now := a.deps.Now().UTC()
	since := now.Add(-window)
	ctx := r.Context()

	var notes []string
	cov := Coverage{}

	events, err := a.fetchEvents(ctx, a.deps.Scope(r), EventQuery{
		Kind:    proto.Kind(),
		SinceMS: since.UnixMilli(),
		Limit:   maxSummaryEvents,
	})
	switch {
	case err != nil:
		notes = append(notes, "adjacency-change events unavailable: the correlation store could not be queried")
	default:
		cov.Events = true
	}
	scanTruncated := len(events) >= maxSummaryEvents
	if scanTruncated {
		events = events[:maxSummaryEvents]
		notes = append(notes, fmt.Sprintf(
			"roll-up covers only the %d most recent adjacency-change events in the window", maxSummaryEvents))
	}

	live := a.fetchLive(ctx, r, p, proto, nil)
	cov.LiveSeries = live.available
	if !live.available {
		notes = append(notes, live.note)
	}
	adv := a.fetchAdvanced(ctx, r, p, proto, nil)
	cov.applyAdvanced(adv)
	notes = append(notes, adv.notes()...)

	devices := AttachAdvanced(
		Summarize(live.rows, events, live.available),
		adv.lsdb.byDevice, adv.spf.byDevice, adv.areas.byDevice)
	deviceTruncated := false
	if len(devices) > limit {
		devices = devices[:limit]
		deviceTruncated = true
	}

	a.deps.Metrics.Query(proto, "summary")
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"protocol":       string(proto),
		"window_seconds": int(window.Seconds()),
		"since":          since.Format(time.RFC3339),
		"now":            now.Format(time.RFC3339),
		"devices":        devices,
		"event_count":    len(events),
		"coverage":       cov,
		"source":         sourceLabel(cov),
		"notes":          notes,
		"limit":          limit,
		"truncated":      deviceTruncated || scanTruncated,
	})
}

// ── GET /api/protocols/{proto}/health ───────────────────────────────────────

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request, proto Proto) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "device", "since"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("since"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	deviceParam := strings.TrimSpace(r.URL.Query().Get("device"))
	if deviceParam == "" {
		a.deps.WriteError(w, http.StatusBadRequest, errors.New("device: required"))
		return
	}
	dev, deviceIDs, ok := a.resolveDevice(w, r, p, deviceParam)
	if !ok {
		return
	}

	now := a.deps.Now().UTC()
	since := now.Add(-window)
	ctx := r.Context()

	var notes []string
	cov := Coverage{}

	events, err := a.fetchEvents(ctx, a.deps.Scope(r), EventQuery{
		Kind:    proto.Kind(),
		Devices: deviceIDs,
		SinceMS: since.UnixMilli(),
		Limit:   maxSummaryEvents,
	})
	switch {
	case err != nil:
		notes = append(notes, "adjacency-change events unavailable: the correlation store could not be queried")
	default:
		cov.Events = true
	}
	if len(events) > maxSummaryEvents {
		events = events[:maxSummaryEvents]
	}

	live := a.fetchLive(ctx, r, p, proto, deviceIDs)
	cov.LiveSeries = live.available
	if !live.available {
		notes = append(notes, live.note)
	}

	flaps := 0
	lastChange := ""
	for _, e := range events {
		if e.State == "down" {
			flaps++
		}
		if lastChange == "" {
			lastChange = e.TS
		}
	}

	// Live-only counts. Null without a series — never 0.
	var neighborCount, adjUp, adjDown *int
	var levels []string
	if live.available {
		total, up, down := 0, 0, 0
		seenLevel := map[string]bool{}
		for _, l := range live.rows {
			total++
			if l.Up {
				up++
			} else {
				down++
			}
			if l.Level != "" && !seenLevel[l.Level] {
				seenLevel[l.Level] = true
				levels = append(levels, l.Level)
			}
		}
		neighborCount, adjUp, adjDown = &total, &up, &down
	}
	if len(levels) == 0 {
		levels = nil
	} else {
		sortStrings(levels)
	}

	// The four advanced probes. `levels` above stays derived from the live
	// adjacency series' isis_level label — it says which levels this device has
	// an ADJACENCY on, which is a different (and independently useful) fact from
	// the area addresses the instance is configured with.
	adv := a.fetchAdvanced(ctx, r, p, proto, deviceIDs)
	cov.applyAdvanced(adv)
	notes = append(notes, adv.notes()...)

	a.deps.Metrics.Query(proto, "health")
	a.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"protocol":          string(proto),
		"device":            dev.ID,
		"device_name":       dev.Name,
		"window_seconds":    int(window.Seconds()),
		"since":             since.Format(time.RFC3339),
		"now":               now.Format(time.RFC3339),
		"levels":            levels,
		"neighbor_count":    neighborCount,
		"adjacencies_up":    adjUp,
		"adjacencies_down":  adjDown,
		"adjacency_changes": len(events),
		"flaps":             flaps,
		"last_change":       lastChange,
		"stability":         stabilityScore(flaps, int(window.Seconds())),
		"lsdb":              adv.lsdbBlock(proto),
		"areas":             adv.areasBlock(),
		"spf_runs":          adv.spfBlock(proto),
		"timers":            adv.timersBlock(proto),
		"coverage":          cov,
		"source":            sourceLabel(cov),
		"notes":             notes,
	})
}

// sortStrings is a tiny in-place sort so the level list is stable across calls.
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
