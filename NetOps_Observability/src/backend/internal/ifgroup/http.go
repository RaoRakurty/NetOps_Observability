package ifgroup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/httppage"
)

// http.go — the single read surface, GET /api/devices/{id}/interfaces/by-vrf.
//
// The handler order IS the isolation guarantee (the igpmon/pcap precedent):
//
//  1. AUTHORIZE at the read gate.
//  2. REFUSE unknown query parameters and bound every accepted value — a caller
//     who asks for a 30-day rate window is told they cannot have it, not handed
//     a silently-substituted default with a 200.
//  3. RESOLVE the {id} through the principal-scoped inventory. Another tenant's
//     id and a nonexistent id answer the SAME 404.
//  4. READ metrics with the caller's extra_filters[] device boundary; a scoped
//     principal with no boundary is refused rather than served the fleet.
//  5. REPORT coverage honestly: an absent source is null + a note, never zero
//     and never a fabricated "default" group.
//
// The tenant is never read from a query string or a body.

// Bounds (§9: every read has a ceiling).
const (
	// The rate window for utilisation and error rates.
	defaultWindow = 5 * time.Minute
	minWindow     = time.Minute
	maxWindow     = 24 * time.Hour

	// maxInterfaces caps the response body. A chassis with more ports than this
	// is truncated and SAYS so in coverage.truncated.
	maxInterfaces = 2000

	// maxInstances caps the known-routing-instance list.
	maxInstances = 200

	// readBudget bounds the whole handler's outbound work, on top of the
	// per-query timeout the injected VMQuery already applies.
	readBudget = 30 * time.Second
)

// routePrefix / routeSuffix delimit the one path this module serves. The id is
// parsed from the path rather than from a mux wildcard so the handler is
// exercisable in a test with a plain *http.Request and no router.
const (
	routePrefix = "/api/devices/"
	routeSuffix = "/interfaces/by-vrf"
)

// Handler returns the module's single HTTP handler.
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
		id, ok := deviceIDFromPath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		a.handleByVRF(w, r, id)
	}
}

// deviceIDFromPath extracts {id} from /api/devices/{id}/interfaces/by-vrf. An
// id containing a further path separator is refused rather than guessed at.
func deviceIDFromPath(path string) (string, bool) {
	if !strings.HasPrefix(path, routePrefix) || !strings.HasSuffix(path, routeSuffix) {
		return "", false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, routePrefix), routeSuffix)
	if id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// parseWindow reads ?window= as a duration ("5m", "1h") or a plain number of
// seconds. A malformed or out-of-range value is an ERROR, never a silent
// fallback: a caller who asked for 30 days must be told they got 24 hours, not
// handed 24 hours with a 200.
func parseWindow(raw string) (time.Duration, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultWindow, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("window: %q is not a duration", raw)
	}
	if d < minWindow || d > maxWindow {
		return 0, fmt.Errorf("window: %s is outside the accepted range %s..%s", d, minWindow, maxWindow)
	}
	return d, nil
}

// promToken sanitizes a device identity for interpolation into a PromQL label
// matcher. The charset admits no quote, no backslash and no brace, so the
// rendered selector cannot be broken out of; '.' is additionally escaped
// because an unescaped one in a `=~` matcher would let one device's selector
// match a different device of the same shape.
func promToken(v string) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == ':' || r == '-' || r == '/':
			return r
		default:
			return -1
		}
	}, v)
	if len(v) > 128 {
		v = v[:128]
	}
	return strings.ReplaceAll(v, ".", `\\.`)
}

// deviceSelector renders {device=~"id|name"} for the resolved device. Both
// identities are included because the SNMP lane labels series with the device
// id and the gNMI lane with the target name (gnmic renames `source` → `device`).
// It returns "" when neither identity survives sanitization, which the caller
// treats as a refusal rather than as a fleet-wide read.
func deviceSelector(d Device) string {
	parts := make([]string, 0, 2)
	seen := map[string]bool{}
	for _, v := range []string{d.ID, d.Name} {
		t := promToken(v)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		parts = append(parts, t)
	}
	if len(parts) == 0 {
		return ""
	}
	return `{device=~"` + strings.Join(parts, "|") + `"}`
}

// errUnselectableDevice is the fail-closed condition for a device whose
// identities sanitize to nothing: querying without a device selector would
// return every device the tenant filter admits, which is not what was asked.
var errUnselectableDevice = errors.New("ifgroup: device identity cannot be expressed as a metric selector")

// metricFilters returns the caller's device boundary, or an error when a SCOPED
// principal has none. A cross-tenant principal legitimately carries no filter.
func (a *API) metricFilters(r *http.Request, p Principal) ([]string, error) {
	f := a.deps.ScopeFilters(r, p)
	if p.Cross {
		return f, nil
	}
	if len(f) == 0 {
		return nil, errScopeless
	}
	return f, nil
}

// handleByVRF serves the one read.
func (a *API) handleByVRF(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := a.deps.Authz(w, r, GateRead)
	if !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window, err := parseWindow(r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}

	// §3a rule 1: a device owned by another tenant and a device that does not
	// exist produce the SAME 404, before any store is touched.
	d, found := a.deps.LookupDevice(id)
	if !found || !a.deps.CanSee(d, p) {
		http.NotFound(w, r)
		return
	}
	sel := deviceSelector(d)
	if sel == "" {
		a.deps.WriteError(w, http.StatusInternalServerError, errUnselectableDevice)
		return
	}
	filters, err := a.metricFilters(r, p)
	if err != nil {
		a.deps.LogWarn("metrics read refused: scoped principal has no device boundary",
			map[string]any{"device": d.ID, "subject": p.Subject})
		a.deps.WriteError(w, http.StatusForbidden, err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), readBudget)
	defer cancel()

	rangeTok := promDuration(window)
	// The state series is the SPINE of the view: if it cannot be read, the
	// answer is an error, NOT an empty page. Rendering "no interfaces are
	// collected for this device" because a query failed is the dishonest state
	// this module exists to avoid.
	oper, err := a.deps.VMQuery(ctx, "device_if_oper_status"+sel, filters)
	if err != nil {
		a.deps.LogWarn("interface state read failed", map[string]any{"device": d.ID, "error": err.Error()})
		a.deps.WriteError(w, http.StatusBadGateway, errors.New("interface state could not be read from the metric store"))
		return
	}

	// The remaining series are ENRICHMENT. A failure leaves the field null and
	// is named in the coverage notes; it never blanks the page and never
	// becomes a zero.
	series := Series{Oper: oper}
	var degraded []string
	read := func(name, query string, into *[]Sample) {
		rows, qerr := a.deps.VMQuery(ctx, query, filters)
		if qerr != nil {
			a.deps.LogWarn("interface enrichment read failed",
				map[string]any{"device": d.ID, "series": name, "error": qerr.Error()})
			degraded = append(degraded, name)
			return
		}
		*into = rows
	}
	read("device_if_admin_status", "device_if_admin_status"+sel, &series.Admin)
	read("device_if_in_octets", "rate(device_if_in_octets"+sel+"["+rangeTok+"]) * 8", &series.InBps)
	read("device_if_out_octets", "rate(device_if_out_octets"+sel+"["+rangeTok+"]) * 8", &series.OutBps)
	read("device_if_speed", "device_if_speed"+sel, &series.Speed)
	read("device_if_in_errors", "rate(device_if_in_errors"+sel+"["+rangeTok+"])", &series.InErr)
	read("device_if_out_errors", "rate(device_if_out_errors"+sel+"["+rangeTok+"])", &series.OutErr)
	read("device_bgp_peer_state", "device_bgp_peer_state"+sel, &series.BGPVRFs)

	term, vendorKnown := a.deps.VRFTerm(d.Vendor)
	ifaces, truncated := BuildInterfaces(series, maxInterfaces)
	groups, vrfLabels := GroupByVRF(ifaces, term)
	instances := KnownRoutingInstances(series.BGPVRFs, maxInstances)
	cov := BuildCoverage(ifaces, groups, vrfLabels, truncated, term, instances)
	for _, name := range degraded {
		cov.Notes = append(cov.Notes,
			"The "+name+" series could not be read on this request; the fields it feeds are null rather than zero.")
	}

	a.deps.WriteJSON(w, http.StatusOK, Response{
		Device:           DeviceView{ID: d.ID, Name: d.Name, Vendor: d.Vendor},
		Window:           rangeTok,
		Dialect:          Dialect{Term: term, TermPlural: pluralTerm(term), Vendor: d.Vendor, VendorKnown: vendorKnown},
		Coverage:         cov,
		Groups:           groups,
		RoutingInstances: instances,
	})
}

// promDuration renders a validated window as a PromQL range token. The value is
// already bounded to minWindow..maxWindow, and only whole seconds are emitted,
// so the token is always a safe literal.
func promDuration(d time.Duration) string {
	secs := int64(d / time.Second)
	if secs%3600 == 0 {
		return fmt.Sprintf("%dh", secs/3600)
	}
	if secs%60 == 0 {
		return fmt.Sprintf("%dm", secs/60)
	}
	return fmt.Sprintf("%ds", secs)
}

// pluralTerm renders the section-heading plural of a dialect word. It mirrors
// the frontend's vendorTerms.vrfTermPlural so a heading reads the same on both
// sides of the wire.
func pluralTerm(term string) string {
	switch term {
	case "routing-instance":
		return "Routing instances"
	case "VPN instance":
		return "VPN instances"
	}
	return term + "s"
}
