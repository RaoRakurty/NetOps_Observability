package main

// cloud_source_status.go — Wave 2 #4 (Data Sources = connectors + health):
// poller-reported per-source ERROR states (review #11 / missing #10).
//
// The readiness model has always DEFINED permission_denied / misconfigured
// (frontend readiness.ts, cloudSourceStatus), but no producer ever emitted
// them — an operator saw "Not configured" when the truth was "IAM denied
// flow logs since Tuesday". This closes the loop: the cloud-ingest poller
// classifies 401/403-class provider failures per lane and PUTs its CURRENT
// error set here; GET /api/cloud/ingestion merges the records into the
// per-source rows the Ingestion Status matrix and the "Permission errors"
// tile already render.
//
// Contract:
//   PUT /api/cloud/ingest/source-status   { records: [...] }  (full-set replace)
//
// Zero-trust posture mirrors the rest of the ingest surface (§3/§3a):
//   - gated by requireCloudIngestService (platform-realm ingest:cloud key);
//   - a record naming a connector_id has its tenant + provider stamped from
//     the CONNECTOR ROW, never from the payload;
//   - ambient-lane records (no connector) carry the poller's tenant claim —
//     the same trust level as the ambient fixture loader's tenant stamp —
//     and are normalized/validated like every other boundary input;
//   - reads are tenant-scoped by the CALLER's claims (ForTenant), so one
//     tenant can never see another tenant's IAM failure details.
//
// Storage is in-memory by design (the cloudIngestInventory precedent): the
// poller re-PUTs its full error set every flush, so a restart converges
// within one cycle; records not refreshed within the stale horizon expire
// on read — an error can never outlive the poller that observed it by more
// than the matrix's own honesty window.

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Bounds (§9): one status report is small; cap both the body and the record
// count so a buggy poller can never balloon platform memory.
const (
	srcStatusBodyMax    = 1 << 20 // 1 MiB
	srcStatusRecordsMax = 500
	srcStatusDetailMax  = 300
)

// srcStatusAllowed are the ONLY poller-reportable statuses. flowing/stale/off
// stay measured from landed data — a poller may report why a source is failing,
// never that it is healthy.
var srcStatusAllowed = map[string]bool{
	"permission_denied": true,
	"misconfigured":     true,
}

// cloudSourceStatusRecord is one (tenant, provider, account, region, source)
// error state as observed by a poller.
type cloudSourceStatusRecord struct {
	Tenant      string    `json:"tenant,omitempty"`       // ambient lanes only; connector rows override it
	ConnectorID string    `json:"connector_id,omitempty"` // when set: tenant+provider come from the row
	Provider    string    `json:"provider"`
	AccountID   string    `json:"account_id,omitempty"`
	Region      string    `json:"region,omitempty"`
	SourceType  string    `json:"source_type"`
	Status      string    `json:"status"` // permission_denied | misconfigured
	Detail      string    `json:"detail,omitempty"`
	SinceISO    string    `json:"since_iso,omitempty"` // poller-observed first failure
	since       time.Time // resolved server-side
	reported    time.Time
	// origin separates the two producers writing into this store: "poller"
	// (full-set replace semantics per flush) and "validate" (the connector
	// wizard's live permission check, upserted per connector). Replace only
	// swaps the poller's records so a validate result survives poller flushes.
	origin string
}

const (
	srcStatusOriginPoller   = "poller"
	srcStatusOriginValidate = "validate"
)

func (r cloudSourceStatusRecord) key() string {
	return strings.Join([]string{r.Tenant, r.Provider, r.AccountID, r.Region, r.SourceType}, "|")
}

// cloudSourceStatusStore holds the poller-reported error set, tenant-keyed.
type cloudSourceStatusStore struct {
	mu   sync.Mutex
	recs map[string]cloudSourceStatusRecord // key() → record
}

func newCloudSourceStatusStore() *cloudSourceStatusStore {
	return &cloudSourceStatusStore{recs: map[string]cloudSourceStatusRecord{}}
}

// Replace swaps in the poller's CURRENT error set (full-set semantics: a lane
// that recovered simply stops being reported and its record disappears). The
// first-failure time is preserved across re-reports so "since Tuesday" stays
// Tuesday — the earliest of the stored and incoming `since` wins. Records the
// VALIDATE surface upserted are retained (a poller flush must not erase a live
// permission-check result); a poller record for the same key overrides it —
// the poller's runtime observation is fresher truth than a wizard snapshot.
func (st *cloudSourceStatusStore) Replace(records []cloudSourceStatusRecord, now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	next := make(map[string]cloudSourceStatusRecord, len(records))
	for k, prev := range st.recs {
		if prev.origin == srcStatusOriginValidate {
			next[k] = prev
		}
	}
	for _, r := range records {
		r.origin = srcStatusOriginPoller
		r.reported = now
		if r.since.IsZero() {
			r.since = now
		}
		k := r.key()
		if prev, ok := st.recs[k]; ok && !prev.since.IsZero() && prev.since.Before(r.since) {
			r.since = prev.since
		}
		next[k] = r
	}
	st.recs = next
}

// UpsertValidate merges the live permission-check results for one connector's
// scope into the store (origin "validate"), preserving first-seen times.
func (st *cloudSourceStatusStore) UpsertValidate(records []cloudSourceStatusRecord, now time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, r := range records {
		r.origin = srcStatusOriginValidate
		r.reported = now
		if r.since.IsZero() {
			r.since = now
		}
		k := r.key()
		if prev, ok := st.recs[k]; ok && !prev.since.IsZero() && prev.since.Before(r.since) {
			r.since = prev.since
		}
		st.recs[k] = r
	}
}

// ClearValidate drops a validate-origin record (the permission is granted
// again). Poller-origin records are never touched here.
func (st *cloudSourceStatusStore) ClearValidate(rec cloudSourceStatusRecord) {
	st.mu.Lock()
	defer st.mu.Unlock()
	k := rec.key()
	if prev, ok := st.recs[k]; ok && prev.origin == srcStatusOriginValidate {
		delete(st.recs, k)
	}
}

// ForTenant returns the caller-visible records, default-closed (§3a.1): a
// non-cross caller only ever sees its own tenant's rows. Records that were not
// refreshed within the ingest stale horizon have expired — the poller that
// observed them is gone or the lane state is unknown, and unknown ≠ broken.
func (st *cloudSourceStatusStore) ForTenant(tenant string, cross bool, now time.Time) []cloudSourceStatusRecord {
	t := normTenant(tenant)
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]cloudSourceStatusRecord, 0, len(st.recs))
	for _, r := range st.recs {
		if now.Sub(r.reported) > ingestStaleWindow {
			continue
		}
		if !cross && r.Tenant != t {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// ── handler: PUT /api/cloud/ingest/source-status ─────────────────────────────

type srcStatusReq struct {
	Records []cloudSourceStatusRecord `json:"records"`
}

func (s *server) handleCloudIngestSourceStatus(w http.ResponseWriter, r *http.Request) {
	if s.cloudSourceStatus == nil {
		writeError(w, http.StatusNotImplemented, errCCNStoreOff)
		return
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("PUT or POST"))
		return
	}
	if _, ok := s.requireCloudIngestService(w, r); !ok {
		return
	}
	var req srcStatusReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, srcStatusBodyMax)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Records) > srcStatusRecordsMax {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "too many status records", "TOO_MANY_RECORDS")
		return
	}
	knownSources := map[string]bool{}
	for _, src := range cloudSourceOrder {
		knownSources[src] = true
	}
	now := time.Now().UTC()
	accepted := make([]cloudSourceStatusRecord, 0, len(req.Records))
	for _, rec := range req.Records {
		rec.Provider = strings.ToLower(strings.TrimSpace(rec.Provider))
		rec.SourceType = strings.ToLower(strings.TrimSpace(rec.SourceType))
		rec.Status = strings.ToLower(strings.TrimSpace(rec.Status))
		rec.AccountID = strings.TrimSpace(rec.AccountID)
		rec.Region = strings.TrimSpace(rec.Region)
		if !srcStatusAllowed[rec.Status] {
			writeJSONError(w, http.StatusBadRequest, "status must be permission_denied or misconfigured", "BAD_STATUS")
			return
		}
		if !knownSources[rec.SourceType] {
			writeJSONError(w, http.StatusBadRequest, "unknown source_type", "BAD_SOURCE")
			return
		}
		if rec.Provider == "" {
			writeJSONError(w, http.StatusBadRequest, "provider is required", "BAD_PROVIDER")
			return
		}
		if len(rec.Detail) > srcStatusDetailMax {
			rec.Detail = rec.Detail[:srcStatusDetailMax]
		}
		// Owner stamping (§3a.2): a connector-scoped record derives tenant AND
		// provider from the row — the payload can never redirect it. Unknown
		// connector ids are refused (no cross-connector guessing).
		if rec.ConnectorID != "" {
			c, found, err := s.cloudConn.Get(r.Context(), "", true, rec.ConnectorID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err)
				return
			}
			if !found {
				writeError(w, http.StatusNotFound, errCCNNotFound)
				return
			}
			rec.Tenant = c.TenantID
			rec.Provider = strings.ToLower(string(c.Provider))
		}
		rec.Tenant = normTenant(rec.Tenant)
		if rec.SinceISO != "" {
			rec.since = mustParseZero(rec.SinceISO)
		}
		accepted = append(accepted, rec)
	}
	s.cloudSourceStatus.Replace(accepted, now)
	writeJSON(w, http.StatusOK, map[string]any{"stored": len(accepted)})
}

// ── merge into GET /api/cloud/ingestion ──────────────────────────────────────

// overlaySourceStatus applies the caller-visible poller error records onto the
// measured per-source rows. An ACTIVE record wins over the measured status —
// the poller clears a record the moment the lane succeeds again, so an active
// record means the lane is failing RIGHT NOW; last-seen/volume are kept (the
// last data before the denial is still true). provider "" = the global row:
// it reflects any of the tenant's providers, permission_denied outranking
// misconfigured when several apply to one source.
func overlaySourceStatus(rows []cloudSourceStatus, recs []cloudSourceStatusRecord, provider string) []cloudSourceStatus {
	if len(recs) == 0 {
		return rows
	}
	pick := map[string]cloudSourceStatusRecord{}
	for _, rec := range recs {
		if provider != "" && rec.Provider != provider {
			continue
		}
		prev, ok := pick[rec.SourceType]
		if !ok || (prev.Status != "permission_denied" && rec.Status == "permission_denied") ||
			(prev.Status == rec.Status && rec.since.Before(prev.since)) {
			pick[rec.SourceType] = rec
		}
	}
	for i := range rows {
		rec, ok := pick[rows[i].SourceType]
		if !ok {
			continue
		}
		rows[i].Status = rec.Status
		rows[i].Detail = rec.Detail
		if !rec.since.IsZero() {
			rows[i].SinceISO = rec.since.Format(time.RFC3339)
		}
	}
	return rows
}
