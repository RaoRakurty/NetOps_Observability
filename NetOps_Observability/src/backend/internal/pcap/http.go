package pcap

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// http.go — the operator surface, under /api/devices/{id}/pcap*.
//
// Every handler follows the same order, and the order IS the isolation
// guarantee (the configstore/secapi precedent):
//
//	1. AUTHORIZE at the right gate. Reads are infrastructure:read; START,
//	   DOWNLOAD and DELETE are infrastructure:write — a download is a REVEAL of
//	   customer payload, so it is deliberately not a read-level act.
//	2. RESOLVE the device and check the caller may SEE it. A device owned by
//	   another tenant answers 404, never 403 — revealing that an id exists
//	   elsewhere is itself the leak (§3a rule 1).
//	3. VALIDATE every path/query/body value (a capture id is 32 hex characters
//	   or it is not a capture id).
//	4. READ through the tenant-scoped store, so the store's own filter/RLS is
//	   the second, independent line.
//	5. AUDIT with a `sensitive` tag on start, fetch and download.
//
// The tenant is NEVER taken from a query string or a body: a `?tenant=` or a
// `{"tenant_id": …}` is not read by any handler here.

// maxRequestBody bounds a control-plane write body (§9).
const maxRequestBody = 4 << 10

// pcapContentType is the IANA media type for a libpcap capture file.
const pcapContentType = "application/vnd.tcpdump.pcap"

// API is the handler set for the device pcap subtree.
type API struct{ m *Manager }

// NewAPI builds the HTTP surface.
func NewAPI(m *Manager) *API { return &API{m: m} }

// ServeDeviceSubroute dispatches the /api/devices/{id}/pcap* subtree. It returns
// false when the path is NOT ours, so the caller's device router keeps its
// existing behaviour untouched — and a flag-off deployment (nil API) claims
// nothing at all, so the feature is not enumerable.
func (a *API) ServeDeviceSubroute(w http.ResponseWriter, r *http.Request) bool {
	if a == nil || a.m == nil {
		return false
	}
	const prefix = "/api/devices/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	rest := r.URL.Path[len(prefix):]
	id, tail, found := strings.Cut(rest, "/pcap")
	if !found || id == "" || strings.Contains(id, "/") {
		return false
	}
	switch {
	case tail == "":
		switch r.Method {
		case http.MethodPost:
			a.handleStart(w, r, id)
		case http.MethodGet:
			a.handleList(w, r, id)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	case strings.HasSuffix(tail, "/download"):
		a.handleDownload(w, r, id, strings.TrimSuffix(strings.TrimPrefix(tail, "/"), "/download"))
	case strings.HasPrefix(tail, "/"):
		captureID := strings.TrimPrefix(tail, "/")
		if strings.Contains(captureID, "/") {
			return false
		}
		switch r.Method {
		case http.MethodGet:
			a.handleStatus(w, r, id, captureID)
		case http.MethodDelete:
			a.handleDelete(w, r, id, captureID)
		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
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

// captureItem is the wire projection. TenantID, BlobRef, RemotePath and Actor's
// provenance stay OFF the wire — an owner stamp, a filesystem path and an
// on-device path are not response fields.
type captureItem struct {
	CaptureID string     `json:"capture_id"`
	Interface string     `json:"interface"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	Status    string     `json:"status"`
	Packets   int        `json:"packets"`
	Bytes     int64      `json:"bytes"`
	Filter    string     `json:"filter,omitempty"`
	Error     string     `json:"error,omitempty"`
}

func toItem(c Capture) captureItem {
	return captureItem{
		CaptureID: c.ID, Interface: c.Interface, StartedAt: c.StartedAt.UTC(),
		EndedAt: c.EndedAt, ExpiresAt: c.ExpiresAt.UTC(), Status: c.Status,
		Packets: c.Packets, Bytes: c.Bytes, Filter: c.Filter, Error: c.Error,
	}
}

// ── POST /api/devices/{id}/pcap ─────────────────────────────────────────────

type startBody struct {
	Interface  string `json:"interface"`
	DurationS  int    `json:"duration_s"`
	MaxPackets int    `json:"max_packets"`
	Filter     string `json:"filter"`
}

func (a *API) handleStart(w http.ResponseWriter, r *http.Request, deviceID string) {
	// A capture is a privileged, payload-revealing action on a production
	// device: it takes the WRITE gate, never read.
	p, dev, ok := a.resolve(w, r, GateWrite, deviceID)
	if !ok {
		return
	}
	var body startBody
	dec := json.NewDecoder(io.LimitReader(r.Body, maxRequestBody))
	// An unknown field is REJECTED, not ignored: a caller that sent
	// {"tenant_id": …} or {"duration": 3600} must be told it was not honoured.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		a.m.deps.WriteError(w, http.StatusBadRequest, errors.New("invalid capture request body"))
		return
	}
	rec, err := a.m.Start(r.Context(), p, dev, StartRequest{
		Interface: body.Interface, DurationSec: body.DurationS,
		MaxPackets: body.MaxPackets, Filter: body.Filter,
	}, p.Subject)
	switch {
	case errors.Is(err, ErrInFlight):
		a.m.deps.WriteError(w, http.StatusConflict, err)
		return
	case errors.Is(err, ErrNoPlatform), errors.Is(err, ErrFilterUnsupported), errors.Is(err, ErrNoAddress):
		a.m.deps.WriteError(w, http.StatusBadRequest, err)
		return
	case err != nil:
		// Every remaining refusal is a GUARDRAIL breach with a reason the
		// operator can act on, so it is a 400 carrying that reason verbatim.
		a.m.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	a.audit(r, p.Tenant, "pcap_capture_started", map[string]any{
		"device": dev.ID, "capture": rec.ID, "interface": rec.Interface,
		"filter": rec.Filter, "duration_s": rec.DurationSec, "max_packets": rec.MaxPackets,
		"sensitive": true,
	})
	a.m.deps.WriteJSON(w, http.StatusAccepted, map[string]any{
		"capture_id": rec.ID, "status": rec.Status, "expires_at": rec.ExpiresAt.UTC(),
	})
}

// ── GET /api/devices/{id}/pcap ──────────────────────────────────────────────

func (a *API) handleList(w http.ResponseWriter, r *http.Request, deviceID string) {
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			a.m.deps.WriteError(w, http.StatusBadRequest, errors.New("limit must be a positive integer"))
			return
		}
		limit = n
	}
	rows, err := a.m.deps.Store.List(r.Context(), p.Tenant, p.Cross, dev.ID, limit)
	if err != nil {
		a.m.deps.LogError("packet capture list failed", map[string]any{
			"device": dev.ID, "error": a.m.deps.Scrub(err.Error())})
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("packet captures are unavailable"))
		return
	}
	items := make([]captureItem, 0, len(rows))
	for _, c := range rows {
		items = append(items, toItem(c))
	}
	a.m.deps.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// ── GET /api/devices/{id}/pcap/{capture_id} ─────────────────────────────────

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request, deviceID, captureID string) {
	p, dev, ok := a.resolve(w, r, GateRead, deviceID)
	if !ok {
		return
	}
	c, ok := a.lookup(w, r, p, dev.ID, captureID)
	if !ok {
		return
	}
	a.m.deps.WriteJSON(w, http.StatusOK, toItem(c))
}

// lookup validates the id shape and reads the row through the tenant-scoped
// store. A malformed id gets the SAME 404 a foreign one does: an id that is
// rejected differently is an oracle for the id format in use.
func (a *API) lookup(w http.ResponseWriter, r *http.Request, p Principal, deviceID, captureID string) (Capture, bool) {
	if !ValidateCaptureID(captureID) {
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return Capture{}, false
	}
	c, err := a.m.deps.Store.Get(r.Context(), p.Tenant, p.Cross, deviceID, captureID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			a.m.deps.LogError("packet capture read failed", map[string]any{
				"device": deviceID, "error": a.m.deps.Scrub(err.Error())})
		}
		a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
		return Capture{}, false
	}
	return c, true
}

// ── GET /api/devices/{id}/pcap/{capture_id}/download ────────────────────────

func (a *API) handleDownload(w http.ResponseWriter, r *http.Request, deviceID, captureID string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// A download is a REVEAL of customer payload — the write gate, and audited
	// before a byte is written (design: "who-downloaded-what audit").
	p, dev, ok := a.resolve(w, r, GateWrite, deviceID)
	if !ok {
		return
	}
	c, ok := a.lookup(w, r, p, dev.ID, captureID)
	if !ok {
		return
	}
	raw, err := a.m.Open(c)
	if err != nil {
		if errors.Is(err, ErrNotReady) {
			a.m.deps.WriteError(w, http.StatusConflict, err)
			return
		}
		a.m.deps.LogError("sealed capture could not be opened", map[string]any{
			"device": dev.ID, "capture": c.ID, "error": a.m.deps.Scrub(err.Error())})
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("the stored capture could not be read"))
		return
	}
	a.audit(r, p.Tenant, "pcap_capture_downloaded", map[string]any{
		"device": dev.ID, "capture": c.ID, "interface": c.Interface,
		"bytes": c.Bytes, "packets": c.Packets, "sensitive": true,
	})
	a.m.deps.Metrics.RecordDownload()
	w.Header().Set("Content-Type", pcapContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	// The file name is built from the SERVER's ids, never a caller string, so
	// there is nothing to inject into the header.
	w.Header().Set("Content-Disposition", `attachment; filename="`+Seg(dev.ID)+"-"+c.ID+`.pcap"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	// #nosec G705 -- these bytes are a binary capture file, not a document: the
	// response is served as application/vnd.tcpdump.pcap with
	// X-Content-Type-Options: nosniff and Content-Disposition: attachment, so no
	// browser renders it as markup. Nothing here is reflected caller input —
	// `raw` is the unsealed blob and the filename is built from server-minted
	// ids. Serving the operator's own capture bytes IS the endpoint.
	if _, werr := w.Write(raw); werr != nil {
		a.m.deps.LogWarn("capture download was interrupted", map[string]any{
			"device": dev.ID, "capture": c.ID, "error": a.m.deps.Scrub(werr.Error())})
	}
}

// ── DELETE /api/devices/{id}/pcap/{capture_id} ──────────────────────────────

func (a *API) handleDelete(w http.ResponseWriter, r *http.Request, deviceID, captureID string) {
	p, dev, ok := a.resolve(w, r, GateWrite, deviceID)
	if !ok {
		return
	}
	if _, ok := a.lookup(w, r, p, dev.ID, captureID); !ok {
		return
	}
	if err := a.m.Delete(r.Context(), p, dev.ID, captureID); err != nil {
		if errors.Is(err, ErrNotFound) {
			a.m.deps.WriteError(w, http.StatusNotFound, ErrNotFound)
			return
		}
		a.m.deps.WriteError(w, http.StatusInternalServerError, errors.New("the capture could not be deleted"))
		return
	}
	a.audit(r, p.Tenant, "pcap_capture_deleted", map[string]any{
		"device": dev.ID, "capture": captureID, "sensitive": true,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) audit(r *http.Request, tenant, action string, detail map[string]any) {
	if a.m.deps.Audit == nil {
		return
	}
	a.m.deps.Audit(r, tenant, action, detail)
}
