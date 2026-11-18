// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devbaseline

// http.go — the device page's baseline API, dispatched from the server's
// /api/devices/ subtree (so it inherits that route's tenant classification):
//
//	GET  /api/devices/{id}/baselines           the device's baselines, newest first (read)
//	POST /api/devices/{id}/baselines           take one now {label?}            (live read)
//	GET  /api/devices/{id}/baselines/{bid}     one baseline in full             (read)
//	POST /api/devices/{id}/baselines/compare   read now and diff {baseline_id?} (live read)
//
// §3a: the device is resolved under the CALLER'S scope first (Hooks.Device:
// another tenant's device and an unknown one are the same 404), and every
// baseline is stored and read under the device's OWNING tenant — never a
// request field. A baseline id of another tenant, or of another device, is 404.
//
// Taking or comparing is a LIVE DEVICE READ (read-only show commands through
// the closed state battery), so it needs the same write permission the
// protocol-diagnostics collect path does; listing stored baselines does not.
// Nothing here changes a device.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Caller is the authenticated principal, as the server derived it.
type Caller struct {
	Subject string
}

// Device is one device the caller may see, with its owning tenant.
type Device struct {
	ID       string
	Name     string
	TenantID string
}

// Hooks are the server's seams. All are required.
type Hooks struct {
	// Authorize checks the caller's permission (live=true: a live device
	// read) and writes the refusal itself when it fails.
	Authorize func(w http.ResponseWriter, r *http.Request, live bool) (Caller, bool)
	// Device resolves id under the caller's scope; false = 404.
	Device func(r *http.Request, id string) (Device, bool)
	// Collect reads the device now with the read-only state battery. A
	// non-empty notWired says why nothing ran (no transport, an unsupported
	// platform); it is not an error.
	Collect func(ctx context.Context, r *http.Request, d Device) (snap Snapshot, notWired string, err error)
}

// API serves the baseline routes.
type API struct {
	Store Store
	Hooks Hooks
	Now   func() time.Time
}

// ErrNotWired is returned by Take and Compare when nothing could be read.
var ErrNotWired = errors.New("devbaseline: the device could not be read")

// NotWiredError carries the operator-readable reason nothing was read.
type NotWiredError struct{ Reason string }

func (e NotWiredError) Error() string { return e.Reason }
func (e NotWiredError) Unwrap() error { return ErrNotWired }

func (a *API) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// Take reads the device now and stores the result as a baseline.
func (a *API) Take(ctx context.Context, r *http.Request, c Caller, d Device, label string) (Snapshot, error) {
	snap, notWired, err := a.Hooks.Collect(ctx, r, d)
	if err != nil {
		return Snapshot{}, err
	}
	if notWired != "" {
		return Snapshot{}, NotWiredError{Reason: notWired}
	}
	snap.ID = ""
	snap.TenantID, snap.DeviceID, snap.DeviceName = d.TenantID, d.ID, d.Name
	snap.TakenBy, snap.Label, snap.TakenAt = c.Subject, label, a.now()
	return a.Store.Put(ctx, d.TenantID, snap)
}

// Compare reads the device now and diffs it against baselineID (the newest
// baseline when empty). The current read is not stored.
func (a *API) Compare(ctx context.Context, r *http.Request, d Device, baselineID string) (Diff, error) {
	var base Snapshot
	var err error
	if baselineID == "" {
		base, err = a.Store.Latest(ctx, d.TenantID, d.ID)
	} else {
		base, err = a.Store.Get(ctx, d.TenantID, d.ID, baselineID)
	}
	if err != nil {
		return Diff{}, err
	}
	cur, notWired, err := a.Hooks.Collect(ctx, r, d)
	if err != nil {
		return Diff{}, err
	}
	if notWired != "" {
		return Diff{}, NotWiredError{Reason: notWired}
	}
	cur.TakenAt = a.now()
	return Compare(base, cur), nil
}

// Path splits /api/devices/{id}/baselines[/{rest}]. ok=false = not a
// baseline route.
func Path(p string) (deviceID, rest string, ok bool) {
	const prefix = "/api/devices/"
	if !strings.HasPrefix(p, prefix) {
		return "", "", false
	}
	tail := p[len(prefix):]
	i := strings.Index(tail, "/baselines")
	if i <= 0 {
		return "", "", false
	}
	deviceID, after := tail[:i], tail[i+len("/baselines"):]
	if strings.Contains(deviceID, "/") {
		return "", "", false
	}
	switch {
	case after == "" || after == "/":
		return deviceID, "", true
	case strings.HasPrefix(after, "/") && !strings.Contains(after[1:], "/"):
		return deviceID, after[1:], true
	}
	return "", "", false
}

// maxRequestBody bounds a POST body (a label and an id).
const maxRequestBody = 4 << 10

// DiffView is the compare response: the structured diff plus its rendered
// OBSERVED lines.
type DiffView struct {
	Diff
	Lines []string `json:"lines"`
}

// ServeDeviceSubroute handles a baseline route; false = not one.
func (a *API) ServeDeviceSubroute(w http.ResponseWriter, r *http.Request) bool {
	id, rest, ok := Path(r.URL.Path)
	if !ok {
		return false
	}
	if a == nil || a.Store == nil {
		writeErr(w, http.StatusServiceUnavailable, "device baselines are not available on this deployment")
		return true
	}
	switch {
	case rest == "" && r.Method == http.MethodGet:
		a.list(w, r, id)
	case rest == "" && r.Method == http.MethodPost:
		a.take(w, r, id)
	case rest == "compare" && r.Method == http.MethodPost:
		a.compare(w, r, id)
	case rest != "" && rest != "compare" && r.Method == http.MethodGet:
		a.get(w, r, id, rest)
	default:
		if rest == "compare" {
			w.Header().Set("Allow", "POST")
		} else if rest == "" {
			w.Header().Set("Allow", "GET, POST")
		} else {
			w.Header().Set("Allow", "GET")
		}
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
	return true
}

func (a *API) device(w http.ResponseWriter, r *http.Request, id string, live bool) (Caller, Device, bool) {
	c, ok := a.Hooks.Authorize(w, r, live)
	if !ok {
		return Caller{}, Device{}, false
	}
	d, ok := a.Hooks.Device(r, id)
	if !ok {
		http.NotFound(w, r) // never reveal another tenant's device
		return Caller{}, Device{}, false
	}
	return c, d, true
}

func (a *API) list(w http.ResponseWriter, r *http.Request, id string) {
	_, d, ok := a.device(w, r, id, false)
	if !ok {
		return
	}
	items, err := a.Store.List(r.Context(), d.TenantID, d.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "the baselines could not be read")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": d.ID, "items": items, "keep": MaxPerDevice})
}

func (a *API) get(w http.ResponseWriter, r *http.Request, id, bid string) {
	_, d, ok := a.device(w, r, id, false)
	if !ok {
		return
	}
	s, err := a.Store.Get(r.Context(), d.TenantID, d.ID, bid)
	switch {
	case errors.Is(err, ErrNotFound):
		http.NotFound(w, r)
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "the baseline could not be read")
	default:
		writeJSON(w, http.StatusOK, s)
	}
}

func readBody(r *http.Request, into any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		return err
	}
	if len(b) > maxRequestBody {
		return errors.New("request body too large")
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

func (a *API) take(w http.ResponseWriter, r *http.Request, id string) {
	c, d, ok := a.device(w, r, id, true)
	if !ok {
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := readBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "the request body must be {\"label\": \"…\"}")
		return
	}
	if len([]rune(strings.TrimSpace(body.Label))) > MaxLabel {
		writeErr(w, http.StatusBadRequest, "the label is longer than 80 characters")
		return
	}
	s, err := a.Take(r.Context(), r, c, d, body.Label)
	a.respond(w, r, http.StatusCreated, s, err)
}

func (a *API) compare(w http.ResponseWriter, r *http.Request, id string) {
	_, d, ok := a.device(w, r, id, true)
	if !ok {
		return
	}
	var body struct {
		BaselineID string `json:"baseline_id"`
	}
	if err := readBody(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "the request body must be {\"baseline_id\": \"…\"}")
		return
	}
	diff, err := a.Compare(r.Context(), r, d, strings.TrimSpace(body.BaselineID))
	if err == nil {
		a.respond(w, r, http.StatusOK, DiffView{Diff: diff, Lines: diff.Lines()}, nil)
		return
	}
	a.respond(w, r, 0, nil, err)
}

func (a *API) respond(w http.ResponseWriter, r *http.Request, status int, v any, err error) {
	var nw NotWiredError
	switch {
	case err == nil:
		writeJSON(w, status, v)
	case errors.As(err, &nw):
		// Nothing was read: 409 with the reason, so the page can say why.
		writeErr(w, http.StatusConflict, nw.Reason)
	case errors.Is(err, ErrNotFound):
		writeErr(w, http.StatusNotFound, "no baseline has been taken of this device yet")
	case errors.Is(err, ErrTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, "the baseline could not be taken or compared")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // discard: the status line is already sent; a broken client connection has no one to report to
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
