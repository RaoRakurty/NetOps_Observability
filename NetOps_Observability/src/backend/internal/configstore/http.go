package configstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// http.go — the operator surface, under /api/devices/{id}/config/*.
//
// Every handler follows the same order, and the order IS the isolation
// guarantee (the secapi precedent):
//
//	1. AUTHORIZE at the right gate (read vs write) → Principal.
//	2. RESOLVE the device and check the caller may SEE it. A device owned by
//	   another tenant answers 404, never 403 — revealing that an id exists
//	   elsewhere is itself the leak (§3a rule 1).
//	3. VALIDATE every path/query value (a version id is 64 hex characters or it
//	   is not a version id).
//	4. READ through the tenant-scoped store, so the store's own filter/RLS is
//	   the second, independent line.
//	5. REDACT before the body is written, and AUDIT the read with a `sensitive`
//	   tag when the body carries configuration text.
//
// The tenant is NEVER taken from a query string or a body: a `?tenant=` or a
// `{"tenant_id": …}` is not read by any handler here.

// maxRequestBody bounds a control-plane write body (§9).
const maxRequestBody = 8 << 10

// DriftStatus is the per-device sync status the badge renders. It is produced by
// the drift consumer and injected — this package owns the ROUTE (it already owns
// the device subtree) but not the verdict.
type DriftStatus struct {
	State       string     `json:"state"`
	LastSHA     *string    `json:"last_sha"`
	GoldenSHA   *string    `json:"golden_sha"`
	LastCapture *time.Time `json:"last_capture_at"`
	LastError   string     `json:"last_error,omitempty"`
}

// StatusSource yields one device's drift status. ok=false means "no status on
// file", which renders as the honest `unknown`.
type StatusSource func(ctx context.Context, tenant string, cross bool, deviceID string) (DriftStatus, bool, error)

// API is the handler set for the device config subtree.
type API struct {
	m      *Manager
	status StatusSource
}

// NewAPI builds the HTTP surface. `status` may be nil (no drift consumer wired):
// the status route then reports `unknown`, which is the truthful answer.
func NewAPI(m *Manager, status StatusSource) *API { return &API{m: m, status: status} }

// ServeDeviceSubroute dispatches the /api/devices/{id}/config/* subtree. It
// returns false when the path is NOT ours, so the caller's device router keeps
// its existing behaviour untouched.
func (a *API) ServeDeviceSubroute(w http.ResponseWriter, r *http.Request) bool {
	if a == nil || a.m == nil {
		return false
	}
	const prefix = "/api/devices/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	rest := r.URL.Path[len(prefix):]
	id, tail, found := strings.Cut(rest, "/config")
	if !found || id == "" || strings.Contains(id, "/") {
		return false
	}
	switch {
	case tail == "/versions":
		a.handleVersions(w, r, id)
	case tail == "/diff":
		a.handleDiff(w, r, id)
	case tail == "/backup":
		a.handleBackup(w, r, id)
	case tail == "/golden":
		a.handleGolden(w, r, id)
	case tail == "/status":
		a.handleStatus(w, r, id)
	case strings.HasPrefix(tail, "/versions/"):
		a.handleVersionText(w, r, id, strings.TrimPrefix(tail, "/versions/"))
	default:
		return false
	}
	return true
}

// resolve authorizes the caller and the device together. It writes the response
// and returns ok=false on any refusal.
func (a *API) resolve(w http.ResponseWriter, r *http.Request, gate Gate, deviceID string) (Principal, Device, bool) {
	p, ok := a.m.deps.Authz(w, r, gate)
	if !ok {
		return Principal{}, Device{}, false
	}
	dev, found := a.m.deps.LookupDevice(deviceID)
	if !found || !visible(p.Tenant, p.Cross, dev.TenantID) {
		// Absent and foreign are deliberately indistinguishable.
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return Principal{}, Device{}, false
	}
	return p, dev, true
}

func methodOK(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method == want {
		return true
	}
	w.Header().Set("Allow", want)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// ── GET /api/devices/{id}/config/versions ───────────────────────────────────

type versionItem struct {
	SHA        string    `json:"sha"`
	CapturedAt time.Time `json:"captured_at"`
	SizeBytes  int64     `json:"size_bytes"`
	Status     string    `json:"status"`
	Error      string    `json:"error,omitempty"`
	Golden     bool      `json:"golden"`
	Drift      string    `json:"drift"`
	Added      int       `json:"added,omitempty"`
	Removed    int       `json:"removed,omitempty"`
}

func (a *API) handleVersions(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !methodOK(w, r, http.MethodGet) {
		return
	}
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	rows, err := a.m.deps.Store.List(r.Context(), p.Tenant, p.Cross, dev.ID)
	if err != nil {
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("configuration versions are unavailable"))
		return
	}
	items := make([]versionItem, 0, len(rows))
	var goldenSHA *string
	for _, v := range rows {
		drift := v.Drift
		if drift == "" {
			drift = DriftUnknown
		}
		items = append(items, versionItem{
			SHA: v.SHA, CapturedAt: v.CapturedAt.UTC(), SizeBytes: v.SizeBytes,
			Status: v.Status, Error: v.Error, Golden: v.Golden,
			Drift: drift, Added: v.Added, Removed: v.Removed,
		})
		if v.Golden {
			sha := v.SHA
			goldenSHA = &sha
		}
	}
	a.m.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"device_id": dev.ID, "items": items,
		"golden_sha": goldenSHA, "next_cursor": nil,
	})
}

// ── GET /api/devices/{id}/config/versions/{sha} ─────────────────────────────

func (a *API) handleVersionText(w http.ResponseWriter, r *http.Request, deviceID, sha string) {
	if !methodOK(w, r, http.MethodGet) {
		return
	}
	if !validSHA(sha) {
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return
	}
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	v, err := a.m.deps.Store.Get(r.Context(), p.Tenant, p.Cross, dev.ID, sha)
	if err != nil || v.Status != StatusOK {
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return
	}
	text, err := a.m.Open(v)
	if err != nil {
		a.m.deps.LogError("stored configuration could not be unsealed", map[string]any{
			"device": dev.ID, "sha": sha, "error": a.m.deps.Scrub(err.Error())})
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("stored configuration could not be read"))
		return
	}
	redacted := Redact(Vendor(v.Vendor), text)
	a.m.deps.Metrics.RecordRedaction()
	// A configuration read is a SENSITIVE operation even redacted: it is the
	// device's operational blueprint. Audited with the `sensitive` tag so it is
	// findable in the trail (§8/§10) — reads of ordinary data are not.
	a.audit(r, p.Tenant, "config_backup_version_read", map[string]any{
		"device": dev.ID, "sha": sha, "sensitive": true, "redacted": true,
	})
	a.m.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"device_id": dev.ID, "sha": v.SHA, "captured_at": v.CapturedAt.UTC(),
		"size_bytes": v.SizeBytes, "golden": v.Golden, "text": redacted,
	})
}

// ── GET /api/devices/{id}/config/diff?from=&to= ─────────────────────────────

func (a *API) handleDiff(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !methodOK(w, r, http.MethodGet) {
		return
	}
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if !validSHA(from) || !validSHA(to) {
		a.m.deps.WriteError(w, http.StatusBadRequest, errors.New("from and to must be configuration version ids"))
		return
	}
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	fromV, err1 := a.m.deps.Store.Get(r.Context(), p.Tenant, p.Cross, dev.ID, from)
	toV, err2 := a.m.deps.Store.Get(r.Context(), p.Tenant, p.Cross, dev.ID, to)
	if err1 != nil || err2 != nil || fromV.Status != StatusOK || toV.Status != StatusOK {
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return
	}
	fromText, err1 := a.m.Open(fromV)
	toText, err2 := a.m.Open(toV)
	if err1 != nil || err2 != nil {
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("stored configuration could not be read"))
		return
	}
	// The diff is computed on the UNREDACTED text (so a rotated secret counts as
	// a real change) and RENDERED through the redaction rules.
	res := Diff(Vendor(toV.Vendor), fromText, toText)
	a.m.deps.Metrics.RecordRedaction()
	a.audit(r, p.Tenant, "config_backup_diff_read", map[string]any{
		"device": dev.ID, "from": from, "to": to, "sensitive": true, "redacted": true,
	})
	a.m.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"device_id": dev.ID, "from": from, "to": to,
		"added": res.Added, "removed": res.Removed,
		"unified": res.Unified, "truncated": res.Truncated,
	})
}

// ── POST /api/devices/{id}/config/backup ────────────────────────────────────

func (a *API) handleBackup(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !methodOK(w, r, http.MethodPost) {
		return
	}
	p, dev, ok := a.resolve(w, r, GateWrite, deviceID)
	if !ok {
		return
	}
	// §3a rule 2: the OWNER is the device row's tenant, never the caller's
	// scope and never a body field. A cross-tenant operator triggering a
	// capture still stamps the device's own tenant on the version.
	owner := NormTenant(dev.TenantID)
	job, claimed := a.m.ClaimFor(dev.ID)
	if !claimed {
		a.m.deps.Metrics.RecordRun(OutcomeSkipped)
		a.m.deps.WriteError(w, http.StatusTooManyRequests, ErrInFlight)
		return
	}
	a.audit(r, p.Tenant, "config_backup_trigger", map[string]any{
		"device": dev.ID, "job_id": job, "owner_tenant": Seg(owner),
	})
	// The capture runs detached from the request: it dials a device and must not
	// hold an HTTP goroutine for its whole timeout. Its own context bounds it.
	go func() {
		defer a.m.Release(dev.ID)
		ctx, cancel := context.WithTimeout(context.Background(), a.m.timeout+10*time.Second)
		defer cancel()
		if _, err := a.m.CaptureClaimed(ctx, dev, owner, "manual", job); err != nil {
			a.m.deps.LogWarn("manual configuration capture failed", map[string]any{
				"device": dev.ID, "job_id": job, "error": a.m.deps.Scrub(err.Error())})
		}
	}()
	a.m.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"job_id": job, "status": "queued",
	})
}

// ── POST /api/devices/{id}/config/golden ────────────────────────────────────

func (a *API) handleGolden(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !methodOK(w, r, http.MethodPost) {
		return
	}
	p, dev, ok := a.resolve(w, r, GateWrite, deviceID)
	if !ok {
		return
	}
	var body struct {
		SHA string `json:"sha"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	dec.DisallowUnknownFields() // a `tenant_id` in the body is a 400, not a silent ignore
	if err := dec.Decode(&body); err != nil {
		a.m.deps.WriteError(w, http.StatusBadRequest, errors.New("body must be {\"sha\": \"<version id>\"}"))
		return
	}
	if !validSHA(body.SHA) {
		a.m.deps.WriteError(w, http.StatusBadRequest, errors.New("sha must be a configuration version id"))
		return
	}
	if err := a.m.deps.Store.SetGolden(r.Context(), p.Tenant, p.Cross, dev.ID, body.SHA); err != nil {
		if errors.Is(err, ErrNotFound) {
			a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
			return
		}
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("golden baseline was not set"))
		return
	}
	a.audit(r, p.Tenant, "config_backup_set_golden", map[string]any{
		"device": dev.ID, "sha": body.SHA,
	})
	a.m.deps.WriteJSON(w, http.StatusOK, map[string]any{
		"device_id": dev.ID, "golden_sha": body.SHA,
	})
}

// ── GET /api/devices/{id}/config/status ─────────────────────────────────────

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request, deviceID string) {
	if !methodOK(w, r, http.MethodGet) {
		return
	}
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	st := DriftStatus{State: DriftUnknown}
	if a.status != nil {
		got, found, err := a.status(r.Context(), p.Tenant, p.Cross, dev.ID)
		if err != nil {
			a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("configuration status is unavailable"))
			return
		}
		if found {
			st = got
		}
	}
	body := map[string]any{
		"device_id": dev.ID, "state": st.State,
		"last_capture_at": st.LastCapture, "last_sha": st.LastSHA,
		"golden_sha": st.GoldenSHA,
	}
	if st.LastError != "" {
		body["last_error"] = st.LastError
	}
	if st.LastCapture != nil {
		next := st.LastCapture.Add(a.m.interval).UTC()
		body["next_scheduled_at"] = next
	}
	a.m.deps.WriteJSON(w, http.StatusOK, body)
}

func (a *API) audit(r *http.Request, tenant, action string, detail map[string]any) {
	if a.m.deps.Audit == nil {
		return
	}
	a.m.deps.Audit(r, tenant, action, detail)
}
