// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// http.go — the HTTP surface. Every handler runs the same steps, in this order,
// and the order IS the isolation guarantee (the secapi precedent):
//
//	1. METHOD check, then AUTHORIZE + resolve the principal (Deps.Authz).
//	2. REJECT unknown query parameters, then parse+validate every known one —
//	   a 400 the caller can act on, never a silently ignored parameter.
//	3. RESOLVE the scope ONCE (scopeOf → oslog.TenantIndexPattern +
//	   oslog.TenantFilter). No handler builds a pattern by hand.
//	4. ISSUE bounded queries built by the pure builders in query.go.
//	5. PROJECT the answer; no upstream body is ever streamed through verbatim.
//
// Nothing here reaches a store, a transport or the clock directly: everything
// external arrives through Deps, so this file holds no ambient authority to
// leak (§5).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/httppage"
)

// ---- gates, principal, dependencies -----------------------------------------

// Gate names the permission a route needs. The concrete module/level mapping
// lives in package backend, where the RBAC model lives; this package states
// WHAT it needs and never WHO grants it.
type Gate int

const (
	// GateStats is the PLATFORM-GLOBAL gate for the engine counters. Parser
	// counters are process-wide facts about the whole fleet's parser, not one
	// tenant's rows, so this is requirePlatformAdmin — NOT a scope-blind
	// requireAdmin, which a tenant admin's full administration:admin would
	// satisfy (§3a rule 3: that is a privilege leak, not a convenience).
	GateStats Gate = iota
	// GateRead is per-tenant operator READ over the tenant's own log lines.
	GateRead
	// GateWrite is the per-tenant gate for drafting a catalog proposal.
	GateWrite
)

// Principal is the caller's already-authorized scope. Deps.Authz produces it
// from the request's claims; nothing in this package derives a tenant from a
// query string, a path or a body (§3a rule 2).
type Principal struct {
	Tenant      string
	Cross       bool
	Subject     string
	DeviceKeys  []string
	DeviceAddrs []string
}

// Deps are the injected collaborators.
type Deps struct {
	// Authz authorizes the caller at `gate`, writing the 401/403 itself and
	// returning ok=false when it did.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// Search issues one OpenSearch request (package backend's env-configured
	// client). The response body is this package's to close.
	Search func(method, path string, body any) (*http.Response, error)
	// Fetch performs one bounded GET against a correlation replica and returns
	// the body. The implementation owns the transport (internal mTLS) and the
	// response cap.
	Fetch func(ctx context.Context, url string) ([]byte, error)
	// Replicas lists the correlation replica base URLs to scrape. Replica
	// topology is deployment knowledge, so it is injected rather than
	// discovered here.
	Replicas func(ctx context.Context) []string
	// Metrics counts mining runs and lines scanned.
	Metrics *Metrics
	// Audit records an accepted draft. Optional (nil = no audit sink); never
	// used to decide anything.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// WriteJSON / WriteError are package backend's response writers (they
	// marshal BEFORE committing the status, per audit F-21).
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// LogWarn is the structured warning sink (§10: no silent failures).
	LogWarn func(msg string, fields map[string]any)
	// Now is the clock seam (nil = wall clock) so windows, cache ages and
	// stamped times are deterministic in tests.
	Now func() time.Time
	// MaxLines caps one mining run's scan (PARSERCOV_MAX_LINES). <= 0 takes
	// DefaultMaxLines.
	MaxLines int
}

// API is the handler set.
type API struct {
	d     Deps
	cache *miningCache
}

// New builds the API over its dependencies.
func New(d Deps) *API {
	a := &API{d: d}
	a.cache = newMiningCache(a.now)
	return a
}

func (a *API) now() time.Time {
	if a.d.Now != nil {
		return a.d.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *API) maxLines() int {
	if a.d.MaxLines > 0 {
		return a.d.MaxLines
	}
	return DefaultMaxLines
}

func (a *API) warn(msg string, fields map[string]any) {
	if a.d.LogWarn != nil {
		a.d.LogWarn(msg, fields)
	}
}

// Bounds and deadlines. Every one of these is a §9 obligation, not a
// preference: an IO path with no timeout and no cap is an outage waiting for a
// slow peer.
const (
	statsTimeout  = 10 * time.Second
	miningTimeout = 60 * time.Second
	searchTimeout = "30s"
	scanBatch     = 1000
	maxOSResponse = 32 << 20
	defaultDays   = 7
	maxDays       = 30
	defaultLimit  = 50
	maxLimit      = 200
)

var (
	errUnreachableReplica = errors.New("correlation replica unreachable")
	errNoVerdict          = errors.New("no admission verdict available for this lane")
)

// ---- GET /api/admin/parser/stats --------------------------------------------

// HandleStats reports the parser engine's own counters, summed across the
// correlation replicas.
//
// PLATFORM-GLOBAL, hence the platform-admin gate (§3a rule 3). A 403 here is a
// legitimate ANSWER for a tenant admin, and the UI renders it as a
// "platform-admin only" card rather than as a failure.
func (a *API) HandleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := a.d.Authz(w, r, GateStats); !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), statsTimeout)
	defer cancel()

	bases := a.replicaBases(ctx)
	if len(bases) == 0 {
		a.d.WriteError(w, http.StatusServiceUnavailable,
			errors.New("no correlation replica endpoint is configured"))
		return
	}
	snaps := make([]*snapshot, 0, len(bases))
	var failed int
	for _, base := range bases {
		s, err := a.scrapeReplica(ctx, base)
		if err != nil {
			failed++
			continue
		}
		snaps = append(snaps, s)
	}
	if len(snaps) == 0 {
		// Every replica silent is an OUTAGE, not "zero hits". Reporting zeros
		// would render as "the parser classified nothing", which is a
		// different — and false — claim.
		a.d.WriteError(w, http.StatusBadGateway,
			fmt.Errorf("no correlation replica answered (%d attempted)", len(bases)))
		return
	}
	if failed > 0 {
		a.warn("parser stats: partial replica coverage", map[string]any{
			"answered": len(snaps), "attempted": len(bases),
		})
	}
	a.d.WriteJSON(w, http.StatusOK, fold(snaps, a.now()))
}

// replicaBases resolves the replica list, defensively de-duplicated and
// bounded — a misconfigured list must not turn one request into an unbounded
// fan-out.
func (a *API) replicaBases(ctx context.Context) []string {
	if a.d.Replicas == nil {
		return nil
	}
	const maxReplicas = 32
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	for _, b := range a.d.Replicas(ctx) {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		if _, dup := seen[b]; dup {
			continue
		}
		seen[b] = struct{}{}
		out = append(out, b)
		if len(out) == maxReplicas {
			break
		}
	}
	return out
}

// ---- GET /api/telemetry/unrecognized ----------------------------------------

// Page is the /api/telemetry/unrecognized body (services/api.ts
// UnrecognizedPage).
type Page struct {
	GeneratedAt string `json:"generated_at"`
	Days        int    `json:"days"`
	Items       []Item `json:"items"`
	Total       int    `json:"total"`
	// Note is the honest state: mining scope, truncation, or "no unrecognized
	// lines in window". The UI renders it verbatim (coverageModel.
	// unrecognizedNote) and never swallows it.
	Note string `json:"note,omitempty"`
}

// runResult is one completed mining run, before a page size is applied.
type runResult struct {
	Days          int
	Lane          Lane
	All           []Item
	Scanned       int
	WindowTotal   int64
	Stamped       int64
	Versions      []string
	Truncated     bool
	GroupsCapped  bool
	DevicesCapped bool
	GeneratedAt   time.Time
}

// HandleUnrecognized mines the caller's own log lines that the engine would NOT
// admit, and reports the shapes it found.
//
// TENANT-SCOPED (§3a). The index pattern and the per-doc clause both come from
// scopeOf; a scoped tenant's query never names another tenant's index and never
// matches another tenant's document.
func (a *API) HandleUnrecognized(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	p, ok := a.d.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "days", "lane"); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	days, err := intParam(r, "days", defaultDays, 1, maxDays)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := intParam(r, "limit", defaultLimit, 1, maxLimit)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	lane, err := laneParam(r)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), miningTimeout)
	defer cancel()

	run, cached, err := a.runOrCached(ctx, p, days, lane)
	if err != nil {
		a.finishRun(w, err)
		return
	}
	if cached {
		a.d.Metrics.IncRun(OutcomeCached)
	} else {
		a.d.Metrics.IncRun(outcomeOf(run))
		a.d.Metrics.AddLines(run.Scanned)
	}
	a.d.WriteJSON(w, http.StatusOK, run.page(limit))
}

// finishRun turns a mining error into the right status and counter. A lane with
// no published verdict is 503 (the answer does not exist yet), everything else
// is 502 (the answer exists, we could not get it) — never a 200 with an empty
// list, which would read as "your estate is fully recognized".
func (a *API) finishRun(w http.ResponseWriter, err error) {
	if errors.Is(err, errNoVerdict) {
		a.d.Metrics.IncRun(OutcomeUnavailable)
		a.d.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	a.d.Metrics.IncRun(OutcomeError)
	a.d.WriteError(w, http.StatusBadGateway, err)
}

func outcomeOf(run runResult) string {
	switch {
	case run.Truncated || run.GroupsCapped:
		return OutcomePartial
	case len(run.All) == 0:
		return OutcomeEmpty
	default:
		return OutcomeOK
	}
}

// runOrCached returns a live cached run for this exact scope+window, or mines a
// fresh one and caches it.
func (a *API) runOrCached(ctx context.Context, p Principal, days int, lane Lane) (runResult, bool, error) {
	index, clause := scopeOf(p, lane)
	clauseJSON, err := json.Marshal(clause)
	if err != nil {
		// Unreachable: the clause is built from plain maps/strings. Surfaced
		// rather than ignored (§5: no ignored errors).
		return runResult{}, false, fmt.Errorf("scope clause not serialisable: %w", err)
	}
	key := cacheKey(index, clauseJSON, days, lane)
	if e := a.cache.get(key); e != nil {
		return e.run, true, nil
	}
	run, err := a.mine(ctx, index, clause, days, lane)
	if err != nil {
		return runResult{}, false, err
	}
	a.cache.put(key, run)
	return run, false, nil
}

// mine runs the whole scan for one scope and window.
func (a *API) mine(ctx context.Context, index string, clause map[string]any, days int, lane Lane) (runResult, error) {
	if lane == LaneTrap {
		// See admission.go: the trap lane publishes no admission verdict —
		// there is no trap-side screen at all — so "the engine would not admit
		// this trap" is not a set we can define. Refuse rather than mine
		// something else and call it that.
		return runResult{}, fmt.Errorf("%w: the SNMP trap lane publishes no ingest admission stamp, "+
			"so unrecognized-shape mining is not defined for it (the syslog lane does)", errNoVerdict)
	}
	now := a.now()
	end := now
	start := end.AddDate(0, 0, -days)

	total, err := a.count(ctx, index, BuildWindowTotalBody(clause, start, end))
	if err != nil {
		return runResult{}, err
	}
	stamped, versions, err := a.countStamped(ctx, index, BuildStampProbeBody(clause, start, end))
	if err != nil {
		return runResult{}, err
	}
	if total > 0 && stamped == 0 {
		// The honest refusal. Every document in the window is unstamped, which
		// means the aggregator's `syslog_admission_stamp` is not running (or
		// this data predates it) — NOT that every line is unrecognized.
		// Reporting the whole window as unrecognized would be a fabrication.
		return runResult{}, fmt.Errorf(
			"%w: no document in the last %d day(s) carries the ingest admission stamp %q "+
				"(deployment/docker/vector/vector.yaml `syslog_admission_stamp`, generated by "+
				"scripts/gen-syslog-admission.py). Without it the engine's admission verdict "+
				"cannot be read, and this endpoint will not guess it",
			errNoVerdict, days, admissionField)
	}

	miner := NewMiner(MinerConfig{})
	max := a.maxLines()
	var after []any
	truncated := false
	for miner.scanned < max {
		select {
		case <-ctx.Done():
			return runResult{}, ctx.Err()
		default:
		}
		size := scanBatch
		if rem := max - miner.scanned; rem < size {
			size = rem
		}
		hits, err := a.scan(ctx, index, BuildScanBody(clause, start, end, size, after))
		if err != nil {
			return runResult{}, err
		}
		if len(hits) == 0 {
			break
		}
		for i := range hits {
			var doc scanDoc
			if err := json.Unmarshal(hits[i].Source, &doc); err != nil {
				// One malformed document must not fail the run; it is counted
				// as scanned and skipped, and the skip is observable.
				a.warn("unrecognized mining: undecodable document skipped",
					map[string]any{"error": err.Error()})
				continue
			}
			miner.Add(doc.toLine())
		}
		after = hits[len(hits)-1].Sort
		if len(hits) < size || len(after) == 0 {
			break
		}
		if miner.scanned >= max {
			truncated = true
		}
	}

	res := miner.Result()
	return runResult{
		Days:          days,
		Lane:          lane,
		All:           res.Items,
		Scanned:       res.LinesScanned,
		WindowTotal:   total,
		Stamped:       stamped,
		Versions:      versions,
		Truncated:     truncated,
		GroupsCapped:  res.GroupsCapped,
		DevicesCapped: res.DevicesCapped,
		GeneratedAt:   now,
	}, nil
}

// page renders the wire body for one page size.
func (r runResult) page(limit int) Page {
	items := r.All
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	if items == nil {
		items = []Item{}
	}
	return Page{
		GeneratedAt: r.GeneratedAt.UTC().Format(time.RFC3339),
		Days:        r.Days,
		Items:       items,
		Total:       len(r.All),
		Note:        r.note(len(items)),
	}
}

// note states the mining scope and every way the answer is incomplete. It is
// always populated: an operator must never have to guess whether an empty table
// means "clean" or "not run".
func (r runResult) note(shown int) string {
	lane := string(r.Lane)
	if lane == "" {
		lane = string(LaneSyslog)
	}
	var parts []string
	if len(r.All) == 0 {
		parts = append(parts, fmt.Sprintf(
			"No unrecognized %s lines in the last %d day(s): every one of the %d line(s) scanned carried the engine's ingest admission stamp.",
			lane, r.Days, r.Scanned))
	} else {
		parts = append(parts, fmt.Sprintf(
			"Mined %d %s line(s) the engine would not admit, over the last %d day(s), into %d shape(s)%s.",
			r.Scanned, lane, r.Days, len(r.All), showing(shown, len(r.All))))
	}
	parts = append(parts, fmt.Sprintf(
		"Admission is the engine's own per-document verdict (%s): %d of %d document(s) in the window carry it%s.",
		admissionField, r.Stamped, r.WindowTotal, versionSuffix(r.Versions)))
	if r.Truncated {
		parts = append(parts, fmt.Sprintf(
			"PARTIAL: the scan stopped at the %d-line cap (PARSERCOV_MAX_LINES), so counts are a lower bound.", r.Scanned))
	}
	if r.GroupsCapped {
		parts = append(parts, fmt.Sprintf(
			"PARTIAL: the %d-shape cap was reached; later shapes were not opened.", DefaultMaxGroups))
	}
	if r.DevicesCapped {
		parts = append(parts, fmt.Sprintf(
			"At least one shape exceeded the %d distinct-device cap, so its device count is a lower bound.", maxDevicesPerGroup))
	}
	return strings.Join(parts, " ")
}

func showing(shown, total int) string {
	if shown >= total {
		return ""
	}
	return fmt.Sprintf(" (showing the %d largest)", shown)
}

func versionSuffix(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	return ", stamped by parser corpus " + strings.Join(versions, " + ")
}

// ---- POST /api/telemetry/unrecognized/{template_id}/propose -----------------

// HandlePropose drafts a catalog row and a fixture for ONE mined shape.
//
// It APPLIES NOTHING (see propose.go). The draft is text; landing it is a pull
// request against telemetry-catalog/events.yaml. The write gate is
// alerts:write because drafting is an authoring act, and it is audited for the
// same reason.
func (a *API) HandlePropose(w http.ResponseWriter, r *http.Request) {
	id, ok := proposePath(r.URL.Path)
	if !ok {
		a.d.WriteError(w, http.StatusNotFound, errors.New("not found"))
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	p, ok := a.d.Authz(w, r, GateWrite)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "days", "lane"); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if !ValidTemplateID(id) {
		// Shape-validated before it reaches any lookup (§3).
		a.d.WriteError(w, http.StatusBadRequest,
			errors.New(`template_id must look like "t-" followed by 10 lower-case hex digits`))
		return
	}
	days, err := intParam(r, "days", defaultDays, 1, maxDays)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	lane, err := laneParam(r)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), miningTimeout)
	defer cancel()

	item, found, err := a.lookup(ctx, p, days, lane, id)
	if err != nil {
		a.finishRun(w, err)
		return
	}
	if !found {
		// A template id that does not resolve in THIS caller's scope is a 404 —
		// the same answer another tenant's id gets, so the route is not an
		// existence oracle for shapes mined in someone else's estate
		// (§3a rule 1).
		a.d.WriteError(w, http.StatusNotFound, errors.New("template not found in the caller's current window"))
		return
	}

	prop := BuildProposal(item)
	if a.d.Audit != nil {
		a.d.Audit(r, p.Tenant, "parser.catalog_row_drafted", map[string]any{
			"template_id": item.TemplateID,
			"proposal_id": prop.ProposalID,
			"lane":        string(lane),
			"days":        days,
			// The drafted row is NOT audited verbatim: it embeds a device log
			// line, and an audit record is a long-lived artifact (§8: sanitize
			// logs). The ids are enough to reproduce it.
			"applied": false,
		})
	}
	a.d.WriteJSON(w, http.StatusOK, prop)
}

// lookup resolves one template id inside the caller's own scope, re-mining when
// the cached run has expired.
func (a *API) lookup(ctx context.Context, p Principal, days int, lane Lane, id string) (Item, bool, error) {
	run, cached, err := a.runOrCached(ctx, p, days, lane)
	if err != nil {
		return Item{}, false, err
	}
	if !cached {
		a.d.Metrics.IncRun(outcomeOf(run))
		a.d.Metrics.AddLines(run.Scanned)
	}
	for _, it := range run.All {
		if it.TemplateID == id {
			return it, true, nil
		}
	}
	return Item{}, false, nil
}

// proposePath matches `/api/telemetry/unrecognized/{id}/propose` and returns the
// id. Anything else is not this route.
func proposePath(path string) (string, bool) {
	const prefix = "/api/telemetry/unrecognized/"
	const suffix = "/propose"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	id := path[len(prefix) : len(path)-len(suffix)]
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// ---- OpenSearch plumbing -----------------------------------------------------

// count issues one size:0 accounting query.
func (a *API) count(ctx context.Context, index string, body map[string]any) (int64, error) {
	raw, err := a.osSearch(ctx, index, body)
	if err != nil {
		return 0, err
	}
	if raw == nil {
		return 0, nil // index family does not exist yet: an empty window
	}
	var parsed osCountResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, err
	}
	return parsed.Hits.Total.Value, nil
}

// countStamped issues the admission probe and returns the stamped count plus
// the corpus versions that stamped them.
func (a *API) countStamped(ctx context.Context, index string, body map[string]any) (int64, []string, error) {
	raw, err := a.osSearch(ctx, index, body)
	if err != nil {
		return 0, nil, err
	}
	if raw == nil {
		return 0, nil, nil
	}
	var parsed osCountResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, nil, err
	}
	versions := make([]string, 0, len(parsed.Aggregations.Versions.Buckets))
	for _, b := range parsed.Aggregations.Versions.Buckets {
		if b.Key != "" {
			versions = append(versions, b.Key)
		}
	}
	return parsed.Hits.Total.Value, versions, nil
}

// scan issues one page of the unrecognized scan.
func (a *API) scan(ctx context.Context, index string, body map[string]any) ([]osScanHit, error) {
	raw, err := a.osSearch(ctx, index, body)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}
	var parsed osScanResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	return parsed.Hits.Hits, nil
}

// osSearch issues one bounded query. A nil body with a nil error means "the
// caller's index family does not exist yet" — an empty result, not an outage. A
// non-2xx status is an ERROR carrying the status, never a zero-result success,
// which would render as "you have no unrecognized lines".
func (a *API) osSearch(ctx context.Context, index string, body map[string]any) ([]byte, error) {
	if a.d.Search == nil {
		return nil, errors.New("no OpenSearch client configured")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	resp, err := a.d.Search("POST", "/"+index+"/_search?timeout="+searchTimeout, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := readCapped(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("opensearch search status %d", resp.StatusCode)
	}
	return raw, nil
}

// ---- parameter parsing --------------------------------------------------------

// intParam reads a bounded integer query parameter. An out-of-range or
// unparseable value is a 400, never a silent clamp: a caller that asked for
// days=400 must LEARN that the window is 30, not receive 30 days labelled 400
// (the F-61 class).
func intParam(r *http.Request, name string, def, min, max int) (int, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(name))
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", name, min, max, n)
	}
	return n, nil
}

// laneParam reads the optional lane filter. Absent means the syslog lane — the
// only lane with a published admission verdict; the UI's "All lanes" choice
// sends no parameter at all.
func laneParam(r *http.Request) (Lane, error) {
	switch strings.TrimSpace(r.URL.Query().Get("lane")) {
	case "", string(LaneSyslog):
		return LaneSyslog, nil
	case string(LaneTrap):
		return LaneTrap, nil
	default:
		return "", fmt.Errorf("lane must be %q or %q", LaneSyslog, LaneTrap)
	}
}
