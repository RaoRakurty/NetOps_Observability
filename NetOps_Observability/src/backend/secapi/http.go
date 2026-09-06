package secapi

// http.go — the HTTP surface. Every handler follows the same five steps, in
// this order, and the order is the isolation guarantee:
//
//	1. AUTHORIZE + resolve the principal's scope (Deps.Authz → Principal).
//	2. REJECT unknown query parameters, then parse+validate every known one
//	   (a 400 the caller can act on, never a silently ignored parameter).
//	3. RESOLVE the caller's index pattern (oslog.TenantIndexPattern) and per-doc
//	   tenant clause (oslog.TenantFilter) — the applogs/flows chokepoint pair.
//	4. ISSUE one bounded query built by the pure builders in query.go.
//	5. PROJECT the answer, never streaming an upstream body through verbatim.
//
// No handler here reaches a store or a store's transport directly: everything
// external arrives through Deps, so this file has no ambient authority to leak.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/httppage"
	"netops/backend/internal/oslog"
)

// Signal is the oslog signal name this API reads. It resolves to the
// netops-secfindings-<seg>-* index family (oslog.IndexBase).
const Signal = "secfindings"

// maxOSResponseBytes bounds one OpenSearch response read. Response size is
// chosen by the peer, not by us (audit F-27): an unbounded io.ReadAll of a
// search result is an OOM in the process that also serves the API.
const maxOSResponseBytes = 32 << 20

// maxRequestBody bounds a control-plane write body.
const maxRequestBody = 64 << 10

// searchTimeout is the per-query OpenSearch deadline passed in the DSL, so a
// slow shard fails the query rather than pinning a request goroutine (§9 all IO
// has a timeout; the injected client carries its own transport deadline too).
const searchTimeout = "20s"

// Gate names the permission a route needs. The concrete module/level mapping
// lives in package backend (where the RBAC model lives) and is injected — this
// package states WHAT it needs, never WHO grants it.
type Gate int

const (
	// GateRead is per-tenant operator READ access to security findings.
	GateRead Gate = iota
	// GateWrite is per-tenant operator WRITE access (saved views).
	GateWrite
	// GateAdmin is the per-tenant administrative gate for changing which
	// detections a tenant runs. It is deliberately NOT a platform-global gate:
	// rule enablement is per-tenant state (§3a rule 3).
	GateAdmin
)

// Principal is the caller's already-authorized scope. It is produced by
// Deps.Authz from the request's claims; nothing in this package derives a
// tenant from a query string or a request body.
type Principal struct {
	// Tenant is principalTenant()'s tenant; Cross is its cross-tenant flag.
	Tenant string
	Cross  bool
	// Subject is the authenticated actor (audit + created_by stamping).
	Subject string
	// DeviceKeys/DeviceAddrs are the caller's visible device identifiers, fed
	// verbatim into oslog.TenantFilter's untagged-document matcher.
	DeviceKeys  []string
	DeviceAddrs []string
}

// Deps are the injected collaborators (§5: interfaces for all external deps).
type Deps struct {
	// Authz authorizes the caller at `gate`, writing the 401/403 itself and
	// returning ok=false when it did.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)
	// Search issues one OpenSearch request (package backend's env-configured
	// client). The response body is the caller's to close.
	Search func(method, path string, body any) (*http.Response, error)
	// ExposureStories runs the tenant-scoped correlations list restricted to
	// security evidence. It is injected because the list SQL and the ClickHouse
	// row-policy scope both live in package backend — this package must not own
	// a second copy of either.
	ExposureStories func(r *http.Request, limit int) ([]map[string]any, error)
	// RegistryDevices counts the devices visible to the caller (the CTEM
	// funnel's `scope` and the coverage denominator).
	RegistryDevices func(r *http.Request) int
	// Store is the PG/file control-plane register.
	Store Store
	// ComplianceInputs supplies the parts of the compliance view that come from
	// the REMOVABLE security producer (internal/hardening): the rule→control
	// mapping and the published benchmark citations. Injected, and nil-safe, so
	// this read API keeps answering with the producer deleted
	// (security_lane_removability_test.go).
	ComplianceInputs func() ComplianceInputs
	// FrameworkStore is the PG/file register for WHICH compliance frameworks a
	// tenant has opted into (frameworks.go). Optional: a nil store means the
	// deployment cannot persist a selection, so every tenant reads the shipped
	// default set and a write is refused with 503 rather than silently accepted.
	FrameworkStore FrameworkStore
	// Metrics counts queries by op.
	Metrics *Metrics
	// Audit records an accepted control-plane write. Optional (nil = no audit
	// sink configured); never used to decide anything.
	Audit func(r *http.Request, tenant, action string, detail map[string]any)
	// WriteJSON / WriteError are package backend's response writers (they
	// marshal BEFORE committing the status, per audit F-21, and carry the
	// encode/write failure counters).
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock seam (nil = wall clock) so default windows and stamped
	// times are deterministic in tests.
	Now func() time.Time
}

// API is the handler set.
type API struct{ d Deps }

// New builds the API over its dependencies.
func New(d Deps) *API { return &API{d: d} }

func (a *API) now() time.Time {
	if a.d.Now != nil {
		return a.d.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *API) count(op string) { a.d.Metrics.Inc(op) }

// scope resolves the caller's index pattern and per-doc tenant clause. It is
// the ONE place both are derived, so no handler can accidentally build a
// pattern by hand (the failure mode §3a rule 4 exists to prevent).
func scope(p Principal) (index string, tenantClause map[string]any) {
	return oslog.TenantIndexPattern(Signal, p.Tenant, p.Cross),
		oslog.TenantFilter(p.Tenant, p.Cross, p.DeviceKeys, p.DeviceAddrs)
}

// ---- OpenSearch response shapes --------------------------------------------

type osHit struct {
	Index  string          `json:"_index"`
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
	Sort   []any           `json:"sort"`
}

type osResponse struct {
	TimedOut bool `json:"timed_out"`
	Hits     struct {
		Total struct {
			Value int64 `json:"value"`
		} `json:"total"`
		Hits []osHit `json:"hits"`
	} `json:"hits"`
	Aggregations json.RawMessage `json:"aggregations"`
}

type termsBucket struct {
	Key      any   `json:"key"`
	DocCount int64 `json:"doc_count"`
}

type termsAgg struct {
	Buckets []termsBucket `json:"buckets"`
}

// search issues one query and decodes it, bounding the response read. A non-2xx
// upstream status is an ERROR with the status in it — never a zero-result
// success, which would render as "you have no findings".
func (a *API) search(index string, body any) (*osResponse, error) {
	resp, err := a.d.Search("POST", "/"+index+"/_search?timeout="+searchTimeout, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOSResponseBytes))
	if err != nil {
		return nil, err
	}
	if len(raw) == maxOSResponseBytes {
		return nil, fmt.Errorf("opensearch response exceeded %d bytes — narrow the query", maxOSResponseBytes)
	}
	if resp.StatusCode/100 != 2 {
		// A 404 here means the caller's index family does not exist yet (no
		// findings have ever been written for this tenant). That is an EMPTY
		// result, not an outage, and is handled by the callers.
		if resp.StatusCode == http.StatusNotFound {
			return &osResponse{}, nil
		}
		return nil, fmt.Errorf("opensearch search status %d", resp.StatusCode)
	}
	var out osResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- shared request plumbing ------------------------------------------------

// begin runs steps 1–3 for a read route: authorize, reject unknown parameters,
// parse the filters, resolve the scope. Everything it can refuse, it refuses
// before a single byte reaches OpenSearch.
func (a *API) begin(w http.ResponseWriter, r *http.Request, gate Gate, extraParams ...string) (Principal, Filters, string, map[string]any, bool) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return Principal{}, Filters{}, "", nil, false
	}
	p, ok := a.d.Authz(w, r, gate)
	if !ok {
		return Principal{}, Filters{}, "", nil, false
	}
	allowed := append(append([]string{}, FilterQueryKeys...), extraParams...)
	if err := httppage.RejectUnknownQuery(r, allowed...); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return Principal{}, Filters{}, "", nil, false
	}
	// `offset` and `envelope` are in the platform-wide allowlist because most
	// handlers route them through httppage.Parse. These routes do not: this API
	// pages by CURSOR and always answers the same envelope. Accepting a
	// parameter and then ignoring it, with a 200, is exactly the F-61 failure —
	// so a caller that sends one is TOLD rather than silently served page 1.
	for _, unsupported := range []string{"offset", "envelope"} {
		if r.URL.Query().Get(unsupported) != "" {
			a.d.WriteError(w, http.StatusBadRequest,
				fmt.Errorf("%s is not supported on this endpoint — page with cursor", unsupported))
			return Principal{}, Filters{}, "", nil, false
		}
	}
	f, err := ParseFilters(r, a.now())
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return Principal{}, Filters{}, "", nil, false
	}
	index, tenantClause := scope(p)
	return p, f, index, tenantClause, true
}

// ---- GET /api/security/findings --------------------------------------------

// findingsPage is the list response. next_cursor is a POINTER so it serializes
// as JSON null at the end of the result set — the contract's `string|null`.
type findingsPage struct {
	Items      []Finding `json:"items"`
	NextCursor *string   `json:"next_cursor"`
	Total      int64     `json:"total"`
}

// HandleFindings serves GET /api/security/findings.
func (a *API) HandleFindings(w http.ResponseWriter, r *http.Request) {
	_, f, index, tenantClause, ok := a.begin(w, r, GateRead, "cursor")
	if !ok {
		return
	}
	limit, err := boundedInt(r, "limit", DefaultListLimit, 1, MaxListLimit)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// A malformed cursor — or one of the wrong KIND for this mode (a keyset
	// cursor replayed with current=true, say) — serves page 1 rather than 500:
	// a stale cursor is a client-side artefact, not an outage.
	var pos PagePos
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		if cur, valid := DecodeCursor(raw); valid && cur.Collapsed == f.Current {
			if f.Current {
				pos.From = cur.Offset
			} else {
				// One value per listSort key, in listSort's order —
				// OpenSearch rejects a search_after whose length differs.
				pos.After = []any{cur.Millis, cur.NativeID, cur.ScanID}
			}
		}
	}
	// The collapsed path pages by OFFSET (OpenSearch refuses collapse with
	// search_after), so it is bounded by the result window. Walking past it is
	// REFUSED rather than served short — a short page with a null cursor while
	// `total` says thousands more is exactly the "that is all the data there
	// is" misread the bounded-read rules exist to prevent.
	if f.Current && pos.From+limit > MaxResultWindow {
		a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf(
			"current-state paging is bounded at %d findings (OpenSearch refuses a keyset with a collapse) — "+
				"narrow the filters or page the full verdict history with current=false", MaxResultWindow))
		return
	}
	a.count("list")
	resp, err := a.search(index, ListBody(f, tenantClause, limit, pos))
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	page := findingsPage{Items: []Finding{}}
	for _, h := range resp.Hits.Hits {
		fn, derr := DecodeFinding(h.Source, h.ID)
		if derr != nil {
			// One unreadable document must not blank the page, but it must not
			// vanish silently either — it is reported as a partial result.
			a.d.WriteError(w, http.StatusBadGateway, fmt.Errorf("decode finding %s: %w", h.ID, derr))
			return
		}
		page.Items = append(page.Items, fn)
	}
	page.Total = resp.Hits.Total.Value
	if f.Current {
		// hits.total counts DOCUMENTS; with a collapse the caller is paging
		// GROUPS, so the honest total is the cardinality of native_id.
		var aggs struct {
			CurrentTotal struct {
				Value float64 `json:"value"`
			} `json:"current_total"`
		}
		if len(resp.Aggregations) > 0 && json.Unmarshal(resp.Aggregations, &aggs) == nil {
			page.Total = int64(aggs.CurrentTotal.Value)
		}
	}
	// A cursor is advertised only on a FULL page (house style): a short page IS
	// the end of the result set, and dangling a cursor that returns nothing
	// makes an exhausted list look like an infinite one.
	if len(resp.Hits.Hits) == limit {
		if f.Current {
			if next := pos.From + len(resp.Hits.Hits); next+1 <= MaxResultWindow {
				cur := EncodeOffsetCursor(next)
				page.NextCursor = &cur
			}
		} else if cur, cok := cursorFromSort(resp.Hits.Hits[len(resp.Hits.Hits)-1].Sort); cok {
			page.NextCursor = &cur
		}
	}
	a.d.WriteJSON(w, http.StatusOK, page)
}

// cursorFromSort renders the keyset cursor from a hit's sort values — one per
// listSort key, i.e. [ts millis, native_id, attrs.scan_id]. It fails closed: an
// unexpected sort shape yields NO cursor rather than a malformed one that would
// restart the list from the beginning.
//
// "Fails closed" was doing real damage before tracker 228, and silently: the
// tie-break named a field NO document carries, so every hit came back
// [ts, null], every page answered next_cursor:null, and the list ended at page
// one while `total` reported thousands more. Nothing errored. The fix is the
// sort (listSort), not this function — but the shape check below is why the
// symptom was a short list rather than a 400 from OpenSearch.
func cursorFromSort(sortVals []any) (string, bool) {
	if len(sortVals) < 3 {
		return "", false
	}
	var ms int64
	switch t := sortVals[0].(type) {
	case float64:
		ms = int64(t)
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return "", false
		}
		ms = n
	default:
		return "", false
	}
	nativeID, nOK := sortVals[1].(string)
	scanID, sOK := sortVals[2].(string)
	if !nOK || !sOK || !isSafeSortValue(nativeID) || !isSafeSortValue(scanID) {
		return "", false
	}
	return EncodeKeysetCursor(ms, nativeID, scanID), true
}

// ---- GET /api/security/findings/{id} ---------------------------------------

// HandleFindingByID serves GET /api/security/findings/{id}.
//
// §3a rule 1: a finding outside the caller's index pattern is UNREACHABLE (the
// pattern names only the caller's own indices) and answers 404 — the same
// answer a genuinely missing id gets, so another tenant's id is never confirmed
// to exist.
//
// The {id} it accepts is the SAME id the list hands out: the OpenSearch
// document `_id` (DecodeFinding takes it from the hit). GetBody resolves it by
// `_id`, not by a `cx_finding_id` field — see the D-09 note there for why the
// two disagreed and every lookup 404'd. isSafeToken below is the §3 boundary
// check: a native_id (with its `|` separators) is a 400, never a query.
func (a *API) HandleFindingByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	p, ok := a.d.Authz(w, r, GateRead)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/security/findings/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}
	if !isSafeToken(id) {
		a.d.WriteError(w, http.StatusBadRequest, errors.New("invalid finding id"))
		return
	}
	index, tenantClause := scope(p)
	now := a.now()
	a.count("get")
	// A by-id lookup spans the whole retention horizon (a finding the caller
	// followed a link to may be older than any list window), still bounded by
	// MaxWindow so the index-pattern expansion stays finite.
	resp, err := a.search(index, GetBody(id, tenantClause, now.Add(-MaxWindow), now.Add(time.Hour)))
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if len(resp.Hits.Hits) == 0 {
		a.d.WriteError(w, http.StatusNotFound, errors.New("finding not found"))
		return
	}
	h := resp.Hits.Hits[0]
	fn, err := DecodeFinding(h.Source, h.ID)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.d.WriteJSON(w, http.StatusOK, fn)
}

// ---- GET /api/security/findings/facets -------------------------------------

// facetSet is the facets response. Every key is always present (an absent facet
// and a zero facet mean different things to an operator).
type facetSet struct {
	Severity      map[string]int64 `json:"severity"`
	Status        map[string]int64 `json:"status"`
	Seam          map[string]int64 `json:"seam"`
	Framework     map[string]int64 `json:"framework"`
	EvidenceClass map[string]int64 `json:"evidence_class"`
	// Truncated is set when a CURRENT-state fold hit MaxCurrentGroups, so a
	// partial count is never presented as the whole picture.
	Truncated bool `json:"truncated,omitempty"`
}

func newFacetSet() facetSet {
	fs := facetSet{
		Severity:      map[string]int64{},
		Status:        map[string]int64{},
		Seam:          map[string]int64{},
		Framework:     map[string]int64{},
		EvidenceClass: map[string]int64{},
	}
	// The status vocabulary is fixed, so every key is emitted (including zeros)
	// rather than only the ones that happened to occur.
	for _, k := range statusFacetOrder {
		fs.Status[k] = 0
	}
	return fs
}

// HandleFacets serves GET /api/security/findings/facets.
func (a *API) HandleFacets(w http.ResponseWriter, r *http.Request) {
	_, f, index, tenantClause, ok := a.begin(w, r, GateRead)
	if !ok {
		return
	}
	a.count("facets")
	fs, err := a.facets(index, f, tenantClause)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.d.WriteJSON(w, http.StatusOK, fs)
}

// facets computes the five facet maps, choosing between a plain terms
// aggregation (every retained verdict) and the current-state fold.
func (a *API) facets(index string, f Filters, tenantClause map[string]any) (facetSet, error) {
	if f.Current {
		return a.currentFacets(index, f, tenantClause)
	}
	resp, err := a.search(index, FacetsBody(f, tenantClause))
	if err != nil {
		return facetSet{}, err
	}
	var aggs struct {
		Severity      termsAgg `json:"severity"`
		Status        termsAgg `json:"status"`
		Seam          termsAgg `json:"seam"`
		Framework     termsAgg `json:"framework"`
		EvidenceClass termsAgg `json:"evidence_class"`
	}
	fs := newFacetSet()
	if len(resp.Aggregations) == 0 {
		return fs, nil
	}
	if err := json.Unmarshal(resp.Aggregations, &aggs); err != nil {
		return facetSet{}, err
	}
	foldTerms(fs.Severity, aggs.Severity, nil)
	foldTerms(fs.Status, aggs.Status, StatusFacetKeys)
	foldTerms(fs.Seam, aggs.Seam, nil)
	foldTerms(fs.Framework, aggs.Framework, nil)
	foldTerms(fs.EvidenceClass, aggs.EvidenceClass, nil)
	return fs, nil
}

// foldTerms accumulates a terms aggregation into a facet map, optionally
// renaming keys through an alias table. A key that has no alias is DROPPED when
// a table is supplied — the status vocabulary is closed, and an unmapped token
// in the index is data corruption, not a new facet to invent.
func foldTerms(dst map[string]int64, agg termsAgg, alias map[string]string) {
	for _, b := range agg.Buckets {
		key, ok := b.Key.(string)
		if !ok || key == "" {
			continue
		}
		if alias != nil {
			mapped, known := alias[key]
			if !known {
				continue
			}
			key = mapped
		}
		dst[key] += b.DocCount
	}
}

// currentRow is one folded current-state verdict — the projection
// currentFoldSource pulls back.
type currentRow struct {
	Severity      string
	Status        string
	SeamType      string
	SeamID        string
	Frameworks    []string
	EvidenceClass string
	EntityID      string
}

// foldCurrent runs the native_id fold and returns the latest verdict per
// identity, plus whether the fold was truncated.
func (a *API) foldCurrent(index string, f Filters, tenantClause map[string]any) ([]currentRow, bool, error) {
	resp, err := a.search(index, CurrentFoldBody(f, tenantClause, MaxCurrentGroups))
	if err != nil {
		return nil, false, err
	}
	if len(resp.Aggregations) == 0 {
		return nil, false, nil
	}
	var aggs struct {
		NativeTotal struct {
			Value float64 `json:"value"`
		} `json:"native_total"`
		ByNative struct {
			Buckets []struct {
				Key    string `json:"key"`
				Latest struct {
					Hits struct {
						Hits []osHit `json:"hits"`
					} `json:"hits"`
				} `json:"latest"`
			} `json:"buckets"`
		} `json:"by_native"`
	}
	if err := json.Unmarshal(resp.Aggregations, &aggs); err != nil {
		return nil, false, err
	}
	rows := make([]currentRow, 0, len(aggs.ByNative.Buckets))
	for _, b := range aggs.ByNative.Buckets {
		if len(b.Latest.Hits.Hits) == 0 {
			continue
		}
		var s srcMap
		if err := json.Unmarshal(b.Latest.Hits.Hits[0].Source, &s); err != nil {
			return nil, false, err
		}
		rows = append(rows, currentRow{
			Severity:      s.str(FieldSeverity),
			Status:        s.first("status", FieldStatus),
			SeamType:      s.first("seam.seam_type", FieldSeamType),
			SeamID:        s.first("seam.seam_id", FieldSeamID),
			Frameworks:    firstStrs(s, "standards", FieldFramework),
			EvidenceClass: s.first("evidence_class", FieldEvidenceClass),
			EntityID:      s.first("resource.uid", FieldEntityID),
		})
	}
	truncated := int64(aggs.NativeTotal.Value) > int64(len(aggs.ByNative.Buckets))
	return rows, truncated, nil
}

// firstStrs is strs() with the direct-field-wins fallback chain.
func firstStrs(s srcMap, paths ...string) []string {
	for _, p := range paths {
		if v := s.strs(p); len(v) > 0 {
			return v
		}
	}
	return nil
}

// currentFacets folds the current-state rows into the same facet shape a terms
// aggregation produces, so the two modes are indistinguishable to a caller
// except in what they count.
func (a *API) currentFacets(index string, f Filters, tenantClause map[string]any) (facetSet, error) {
	rows, truncated, err := a.foldCurrent(index, f, tenantClause)
	if err != nil {
		return facetSet{}, err
	}
	fs := newFacetSet()
	fs.Truncated = truncated
	for _, row := range rows {
		if row.Severity != "" {
			fs.Severity[row.Severity]++
		}
		if key, ok := StatusFacetKeys[row.Status]; ok {
			fs.Status[key]++
		}
		if row.SeamType != "" {
			fs.Seam[row.SeamType]++
		}
		for _, fw := range row.Frameworks {
			fs.Framework[fw]++
		}
		if row.EvidenceClass != "" {
			fs.EvidenceClass[row.EvidenceClass]++
		}
	}
	capMap(fs.Severity, MaxFacetTerms)
	capMap(fs.Seam, MaxFacetTerms)
	capMap(fs.Framework, MaxFacetTerms)
	capMap(fs.EvidenceClass, MaxFacetTerms)
	return fs, nil
}

// capMap trims a folded facet to the same bucket ceiling the server-side terms
// aggregation enforces, keeping the largest counts (ties broken by key so the
// result is deterministic).
func capMap(m map[string]int64, max int) {
	if len(m) <= max {
		return
	}
	type kv struct {
		k string
		v int64
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	for _, e := range all[max:] {
		delete(m, e.k)
	}
}

// ---- GET /api/security/findings/trend --------------------------------------

// trendBucket is one point of the trend series.
type trendBucket struct {
	T    string `json:"t"`
	Fail int64  `json:"fail"`
	Warn int64  `json:"warn"`
	Pass int64  `json:"pass"`
}

// HandleTrend serves GET /api/security/findings/trend.
func (a *API) HandleTrend(w http.ResponseWriter, r *http.Request) {
	_, f, index, tenantClause, ok := a.begin(w, r, GateRead, "bucket")
	if !ok {
		return
	}
	interval, err := ParseBucket(r.URL.Query().Get("bucket"))
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	n, err := TrendBucketCount(f, interval)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if n > MaxTrendBuckets {
		a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf(
			"that range at bucket=%s is %d points (max %d) — widen the bucket or narrow since/until",
			r.URL.Query().Get("bucket"), n, MaxTrendBuckets))
		return
	}
	a.count("trend")
	resp, err := a.search(index, TrendBody(f, tenantClause, interval))
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	buckets := []trendBucket{}
	if len(resp.Aggregations) > 0 {
		var aggs struct {
			Trend struct {
				Buckets []struct {
					KeyAsString string   `json:"key_as_string"`
					Key         int64    `json:"key"`
					Status      termsAgg `json:"status"`
				} `json:"buckets"`
			} `json:"trend"`
		}
		if err := json.Unmarshal(resp.Aggregations, &aggs); err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
		for _, b := range aggs.Trend.Buckets {
			tb := trendBucket{T: b.KeyAsString}
			if tb.T == "" {
				tb.T = time.UnixMilli(b.Key).UTC().Format(time.RFC3339)
			}
			counts := map[string]int64{}
			foldTerms(counts, b.Status, StatusFacetKeys)
			tb.Fail, tb.Warn, tb.Pass = counts["fail"], counts["warn"], counts["pass"]
			buckets = append(buckets, tb)
		}
	}
	a.d.WriteJSON(w, http.StatusOK, map[string]any{"buckets": buckets})
}

// ---- GET /api/security/posture ---------------------------------------------

// HandlePosture serves GET /api/security/posture — the CTEM funnel, assessment
// coverage and the last scan.
//
// HONESTY RULES BAKED IN (§5g, and the reason this endpoint exists at all):
//   - `scope` is the tenant's REGISTRY size, not the number of devices that
//     happen to have findings, so an unassessed fleet reads as unassessed;
//   - `coverage.unassessed` is reported explicitly and is NEVER folded into a
//     pass count — an asset nobody looked at is not a clean asset;
//   - `validate` is 0 and says so in `notes`: the finding model carries no
//     validation marker today (there is no field in secfindings.Finding, and
//     none on the bus), so a non-zero number here would be invented.
func (a *API) HandlePosture(w http.ResponseWriter, r *http.Request) {
	p, f, index, tenantClause, ok := a.begin(w, r, GateRead)
	if !ok {
		return
	}
	a.count("posture")
	// The funnel describes CURRENT state regardless of what the caller asked
	// for: a funnel over every historical verdict would count one control that
	// failed in 30 scans as 30 exposures.
	current := f
	current.Current = true

	rows, truncated, err := a.foldCurrent(index, current, tenantClause)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	discover, prioritize, mobilize := len(rows), 0, 0
	for _, row := range rows {
		if PrioritySeverities[row.Severity] {
			prioritize++
		}
		// "Mobilize" is a finding whose seam OWNER is resolvable: without a
		// seam there is nobody to hand the work to, so counting it here would
		// claim readiness the platform cannot back.
		if row.SeamID != "" || row.SeamType != "" {
			mobilize++
		}
	}

	cov, err := a.search(index, CoverageBody(current, tenantClause))
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	assessed, scanID, scanTime := 0, "", ""
	if len(cov.Aggregations) > 0 {
		var aggs struct {
			AssessedDevices struct {
				Value float64 `json:"value"`
			} `json:"assessed_devices"`
			LastScan struct {
				Hits struct {
					Hits []osHit `json:"hits"`
				} `json:"hits"`
			} `json:"last_scan"`
		}
		if err := json.Unmarshal(cov.Aggregations, &aggs); err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
		assessed = int(aggs.AssessedDevices.Value)
		if len(aggs.LastScan.Hits.Hits) > 0 {
			var s srcMap
			if err := json.Unmarshal(aggs.LastScan.Hits.Hits[0].Source, &s); err == nil {
				scanID = s.first(FieldScanID, "scan_uid", "scan_id")
				if t := decodeTime(s); !t.IsZero() {
					scanTime = t.Format(time.RFC3339)
				}
			}
		}
	}

	total := 0
	if a.d.RegistryDevices != nil {
		total = a.d.RegistryDevices(r)
	}
	// The registry is the denominator, but a device can carry findings while
	// having aged out of (or never entered) inventory. Reporting more assessed
	// assets than exist would be nonsense, so the SCOPE grows to hold them
	// rather than the assessed count being silently clipped.
	if assessed > total {
		total = assessed
	}
	unassessed := total - assessed

	notes := map[string]string{
		"validate": "always 0: the finding model carries no validation marker " +
			"(secfindings.Finding has no such field and the bus event carries none), " +
			"so a non-zero value here would be invented rather than measured.",
		"coverage": "assessed_assets counts DISTINCT devices with at least one finding in the " +
			"window; unassessed is the remainder of the tenant's device registry and is " +
			"NOT a pass — nobody looked at those assets.",
	}
	if truncated {
		notes["funnel"] = fmt.Sprintf(
			"truncated: more than %d distinct current findings matched; the funnel counts the first %d.",
			MaxCurrentGroups, MaxCurrentGroups)
	}
	if p.Cross {
		notes["scope"] = "cross-tenant (platform) view: the funnel spans every tenant's findings."
	}

	a.d.WriteJSON(w, http.StatusOK, map[string]any{
		"funnel": map[string]any{
			"scope":      total,
			"discover":   discover,
			"prioritize": prioritize,
			"validate":   0,
			"mobilize":   mobilize,
		},
		"coverage": map[string]any{
			"assessed_assets": assessed,
			"total_assets":    total,
			"unassessed":      unassessed,
		},
		"last_scan": map[string]any{
			"scan_id": scanID,
			"time":    scanTime,
		},
		"notes": notes,
	})
}

// ---- GET /api/security/exposure-stories ------------------------------------

// HandleExposureStories serves GET /api/security/exposure-stories — the
// correlation objects whose evidence includes a security signal.
//
// An EMPTY list is a legitimate answer: the engine-side grounding (T2b) that
// turns security evidence into correlated Exposure Stories may not be built or
// may simply have produced nothing. It answers `[]`, never an error — "no
// stories" and "the query failed" must not look the same to the page.
func (a *API) HandleExposureStories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := a.d.Authz(w, r, GateRead); !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "since"); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	limit, err := boundedInt(r, "limit", 50, 1, 200)
	if err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.count("exposure_stories")
	if a.d.ExposureStories == nil {
		a.d.WriteJSON(w, http.StatusOK, []map[string]any{})
		return
	}
	rows, err := a.d.ExposureStories(r, limit)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	a.d.WriteJSON(w, http.StatusOK, rows)
}

// ---- GET|PUT /api/security/rules -------------------------------------------

// ruleWrite is one entry of the PUT body.
type ruleWrite struct {
	RuleID  string `json:"rule_id"`
	Enabled *bool  `json:"enabled"`
}

// HandleRules serves GET|PUT /api/security/rules.
//
// The gate is requirePerm at the ADMIN level, not a platform-global gate: rule
// enablement is PER-TENANT state (§3a rule 3 — a platform gate here would put a
// tenant's own detection configuration out of that tenant's reach, and a
// scope-blind admin gate would put it in everyone else's).
func (a *API) HandleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p, ok := a.d.Authz(w, r, GateRead)
		if !ok {
			return
		}
		if err := httppage.RejectUnknownQuery(r); err != nil {
			a.d.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.count("rules")
		states, err := a.d.Store.RuleStates(r.Context(), p.Tenant, p.Cross)
		if err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
		a.d.WriteJSON(w, http.StatusOK, Apply(Catalog(), states))
	case http.MethodPut:
		a.putRules(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT only"))
	}
}

func (a *API) putRules(w http.ResponseWriter, r *http.Request) {
	p, ok := a.d.Authz(w, r, GateAdmin)
	if !ok {
		return
	}
	if p.Cross {
		// There is no single tenant to stamp in the cross-tenant (Global) view,
		// and guessing one would write another tenant's configuration. §3a
		// rule 2: the owner comes from the principal or the write is refused.
		a.d.WriteError(w, http.StatusBadRequest,
			errors.New("select a tenant before changing rule state — rule enablement is per-tenant"))
		return
	}
	var body []ruleWrite
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) == 0 {
		a.d.WriteError(w, http.StatusBadRequest, errors.New("body must be a non-empty array of {rule_id, enabled}"))
		return
	}
	if len(body) > MaxRuleWrites {
		a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("at most %d rule updates per request", MaxRuleWrites))
		return
	}
	known := CatalogIDs()
	seen := map[string]bool{}
	states := make([]RuleState, 0, len(body))
	now := a.now()
	for _, e := range body {
		id := strings.TrimSpace(e.RuleID)
		if !known[id] {
			// A closed vocabulary: an unknown id would create a row nothing
			// reads and let a caller grow the table without bound.
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("unknown rule_id %q", e.RuleID))
			return
		}
		if e.Enabled == nil {
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("rule %q: enabled is required", id))
			return
		}
		if seen[id] {
			a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("rule %q appears twice", id))
			return
		}
		seen[id] = true
		states = append(states, RuleState{
			RuleID: id, Enabled: *e.Enabled, UpdatedBy: p.Subject, UpdatedAt: now,
		})
	}
	a.count("rules")
	if err := a.d.Store.SetRuleStates(r.Context(), p.Tenant, p.Cross, p.Tenant, states); err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if a.d.Audit != nil {
		ids := make([]string, 0, len(states))
		for _, s := range states {
			ids = append(ids, s.RuleID+"="+strconv.FormatBool(s.Enabled))
		}
		sort.Strings(ids)
		a.d.Audit(r, p.Tenant, "security_rules_update", map[string]any{"rules": ids})
	}
	states2, err := a.d.Store.RuleStates(r.Context(), p.Tenant, p.Cross)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.d.WriteJSON(w, http.StatusOK, Apply(Catalog(), states2))
}

// ---- GET|POST|DELETE /api/security/views -----------------------------------

// viewWrite is the POST body.
type viewWrite struct {
	Name    string          `json:"name"`
	Filters json.RawMessage `json:"filters"`
}

// HandleViews serves GET|POST /api/security/views and DELETE
// /api/security/views/{id} (a DELETE on the collection path with ?id= is
// accepted too, so a client that has only the collection route still works).
func (a *API) HandleViews(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p, ok := a.d.Authz(w, r, GateRead)
		if !ok {
			return
		}
		if err := httppage.RejectUnknownQuery(r); err != nil {
			a.d.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.count("views")
		views, err := a.d.Store.Views(r.Context(), p.Tenant, p.Cross)
		if err != nil {
			a.d.WriteError(w, http.StatusBadGateway, err)
			return
		}
		a.d.WriteJSON(w, http.StatusOK, views)
	case http.MethodPost:
		a.postView(w, r)
	case http.MethodDelete:
		a.deleteView(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		a.d.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, POST or DELETE only"))
	}
}

func (a *API) postView(w http.ResponseWriter, r *http.Request) {
	p, ok := a.d.Authz(w, r, GateWrite)
	if !ok {
		return
	}
	var body viewWrite
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, err)
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > MaxViewNameLen {
		a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("name is required and must be at most %d characters", MaxViewNameLen))
		return
	}
	filters := body.Filters
	if len(filters) == 0 {
		filters = json.RawMessage(`{}`)
	}
	if len(filters) > MaxViewFiltersLen {
		a.d.WriteError(w, http.StatusBadRequest, fmt.Errorf("filters must be at most %d bytes", MaxViewFiltersLen))
		return
	}
	// The filter blob is OPAQUE, CALLER-SUPPLIED data. It is stored as JSONB, so
	// it must at minimum BE a JSON object — a scalar or an array would round-trip
	// into a shape the reader cannot use, and storing unvalidated bytes in a
	// typed column is how a store starts holding things nothing can read.
	var probe map[string]any
	if err := json.Unmarshal(filters, &probe); err != nil {
		a.d.WriteError(w, http.StatusBadRequest, errors.New("filters must be a JSON object"))
		return
	}
	a.count("views")
	saved, err := a.d.Store.AddView(r.Context(), p.Tenant, p.Cross, SavedView{
		// §3a rule 2: the owner is the authenticated principal's tenant. A
		// tenant in the body would have been rejected by DisallowUnknownFields
		// before reaching here.
		TenantID: p.Tenant, Name: name, Filters: filters,
		CreatedBy: p.Subject, CreatedAt: a.now(),
	})
	switch {
	case errors.Is(err, ErrViewLimit), errors.Is(err, ErrDuplicateView):
		a.d.WriteError(w, http.StatusConflict, err)
		return
	case err != nil:
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if a.d.Audit != nil {
		a.d.Audit(r, p.Tenant, "security_view_create", map[string]any{"view_id": saved.ID, "name": saved.Name})
	}
	a.d.WriteJSON(w, http.StatusCreated, saved)
}

func (a *API) deleteView(w http.ResponseWriter, r *http.Request) {
	p, ok := a.d.Authz(w, r, GateWrite)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/security/views")
	id = strings.TrimPrefix(id, "/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}
	if id == "" {
		id = strings.TrimSpace(r.URL.Query().Get("id"))
	}
	if !isSafeToken(id) {
		a.d.WriteError(w, http.StatusBadRequest, errors.New("invalid view id"))
		return
	}
	a.count("views")
	found, err := a.d.Store.DeleteView(r.Context(), p.Tenant, p.Cross, id)
	if err != nil {
		a.d.WriteError(w, http.StatusBadGateway, err)
		return
	}
	if !found {
		// §3a rule 1: another tenant's view id and a nonexistent one are the
		// same answer, so existence is never revealed.
		a.d.WriteError(w, http.StatusNotFound, errors.New("saved view not found"))
		return
	}
	if a.d.Audit != nil {
		a.d.Audit(r, p.Tenant, "security_view_delete", map[string]any{"view_id": id})
	}
	a.d.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ---- small helpers ----------------------------------------------------------

// boundedInt is the fail-closed bounded int parser (main's intQuery contract,
// duplicated at this package boundary exactly as internal/httppage duplicates
// it): absent = default; malformed or out of range = an error naming the key
// and its bounds. Silently clamping would return fewer rows than were asked for
// with a 200, which reads as "that is all the data there is" (audit F-71).
func boundedInt(r *http.Request, key string, def, min, max int) (int, error) {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return n, nil
}
