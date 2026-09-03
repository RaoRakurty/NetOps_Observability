package pipedebug

// http.go — the platform-admin debug route family (design §4).
//
//	POST /api/debug/trace          inject ONE marked synthetic record, start the
//	                               async follow, return the marker + receipt
//	GET  /api/debug/trace/{marker} poll the follow's stage status
//	PUT  /api/debug/loglevel       raise a module to debug for a BOUNDED window,
//	                               with auto-revert; honest refusal for a module
//	                               that cannot be switched at runtime
//	GET  /api/debug/stage/{stage}?marker=…  one stage's evidence, on demand
//
// ISOLATION (§3a rule 3). Every route is requirePlatformAdmin, injected as
// Deps.Authz. This is deliberately NOT requirePerm/requireAdmin: a trace reads
// one tenant's telemetry out of the shared stores and a loglevel change is
// stack-wide plumbing, so a tenant admin's full administration:admin must not
// reach it. The `tenant` field on a trace request NARROWS a cross-tenant
// principal (the `as_tenant` shape); it can never widen a scoped one, and a
// scoped principal asking for a different tenant is refused.
//
// ZERO TRUST (§3/§8). Every field arrives from a caller and is validated
// against a closed grammar before use: kind, module, level and stage come from
// enumerated sets, the marker from ValidMarker, the device from ValidDeviceKey,
// and the windows are clamped. Bodies are MaxBytesReader-capped.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// maxDebugBody bounds every debug request body. These payloads are five short
// fields; anything larger is a probe, not a request.
const maxDebugBody = 8 << 10

// API is the handler set. Build it with New.
type API struct {
	deps   Deps
	traces *traceStore
}

// New builds the debug API over its injected seams.
func New(deps Deps) *API {
	return &API{deps: deps, traces: newTraceStore()}
}

// ── POST /api/debug/trace ───────────────────────────────────────────────────

type traceRequest struct {
	Kind   string `json:"kind"`
	Device string `json:"device"`
	Tenant string `json:"tenant"`
	TTLSec int    `json:"ttl_seconds"`
}

type traceReceipt struct {
	Marker    string    `json:"marker"`
	Kind      Kind      `json:"kind"`
	Device    string    `json:"device"`
	Tenant    string    `json:"tenant"`
	Injected  bool      `json:"injected"`
	InjectErr string    `json:"inject_error,omitempty"`
	TTLSec    int       `json:"ttl_seconds"`
	Started   time.Time `json:"started"`
	Synthetic bool      `json:"synthetic"`
	StatusURL string    `json:"status_url"`
}

// HandleTrace serves POST /api/debug/trace.
func (a *API) HandleTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	var req traceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDebugBody)).Decode(&req); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	kind, err := ParseKind(req.Kind)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	device := strings.TrimSpace(req.Device)
	if err := ValidDeviceKey(device); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	tenant, err := effectiveTenant(p, req.Tenant)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	ttl := ClampTraceTTL(time.Duration(req.TTLSec) * time.Second)

	now := a.deps.now()
	marker := NewMarker(now)

	receipt := traceReceipt{
		Marker: marker, Kind: kind, Device: device, Tenant: tenant,
		TTLSec: int(ttl.Seconds()), Started: now, Synthetic: true,
		StatusURL: "/api/debug/trace/" + marker,
	}

	// The injection is the ONE write this feature performs, and it goes to the
	// stack's own ingress — never to a device (design §5).
	if err := a.inject(r, kind, marker, device); err != nil {
		receipt.InjectErr = err.Error()
	} else {
		receipt.Injected = true
	}

	a.ring(marker, "trace", "synthetic record injected", map[string]any{
		"kind": string(kind), "device": device, "tenant": tenant,
		"injected": receipt.Injected, "inject_error": receipt.InjectErr,
	})
	a.audit(r, tenant, "debug.trace", map[string]any{
		"marker": marker, "kind": string(kind), "device": device,
		"injected": receipt.Injected, "synthetic": true,
	})

	if receipt.Injected {
		a.traces.start(a, marker, kind, device, tenant, p, ttl)
	}
	a.deps.WriteJSON(w, http.StatusAccepted, receipt)
}

func (a *API) inject(r *http.Request, kind Kind, marker, device string) error {
	ctx := r.Context()
	now := a.deps.now()
	switch kind {
	case KindSyslog:
		if a.deps.InjectSyslog == nil {
			return errors.New("syslog injection is not wired into this API build")
		}
		return a.deps.InjectSyslog(ctx, BuildSyslogFrame(marker, device, now))
	case KindTrap:
		if a.deps.InjectTrap == nil {
			return errors.New("trap injection is not wired into this API build")
		}
		pdu, err := BuildTrapPDU(marker, device, "", now)
		if err != nil {
			return err
		}
		return a.deps.InjectTrap(ctx, pdu)
	default:
		return fmt.Errorf("kind %q cannot be injected", kind)
	}
}

// effectiveTenant applies §3a rule 2/3: the tenant is taken from the PRINCIPAL,
// and a request-supplied tenant may only NARROW a cross-tenant principal.
func effectiveTenant(p Principal, requested string) (string, error) {
	req := strings.ToLower(strings.TrimSpace(requested))
	if !p.Cross {
		if req != "" && req != strings.ToLower(p.Tenant) {
			return "", errors.New("tenant selector may not name a tenant other than the caller's own")
		}
		return p.Tenant, nil
	}
	if req == "" {
		return "", nil
	}
	if err := ValidDeviceKey(req); err != nil {
		return "", fmt.Errorf("tenant: %w", err)
	}
	return req, nil
}

// ── GET /api/debug/trace/{marker} ───────────────────────────────────────────

// HandleTraceStatus serves GET /api/debug/trace/{marker}.
func (a *API) HandleTraceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	marker, err := NormalizeMarker(strings.TrimPrefix(r.URL.Path, "/api/debug/trace/"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	st, found := a.traces.get(marker)
	if !found {
		// A marker this API never started is a 404, and deliberately the same
		// 404 a marker belonging to another scope would get: an id's existence
		// is never confirmed to a caller who may not read it (§3a rule 1).
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no such trace"))
		return
	}
	if !p.Cross && !strings.EqualFold(st.Tenant, p.Tenant) {
		a.deps.WriteError(w, http.StatusNotFound, errors.New("no such trace"))
		return
	}
	a.deps.WriteJSON(w, http.StatusOK, st)
}

// ── PUT /api/debug/loglevel ─────────────────────────────────────────────────

type levelRequest struct {
	Module     string `json:"module"`
	Level      string `json:"level"`
	ForSeconds int    `json:"for_seconds"`
}

// HandleLogLevel serves PUT /api/debug/loglevel.
func (a *API) HandleLogLevel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	var req levelRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDebugBody)).Decode(&req); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	module, err := ParseModule(req.Module)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	level, err := ParseLevel(req.Level)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	window := ClampWindow(time.Duration(req.ForSeconds) * time.Second)

	change, err := a.setLevel(r, module, level, window)
	if err != nil {
		a.deps.WriteError(w, http.StatusBadGateway, err)
		return
	}
	a.audit(r, p.Tenant, "debug.loglevel", map[string]any{
		"module": string(module), "level": string(level),
		"for_seconds": int(window.Seconds()), "applied": change.Applied,
		"reason": change.Reason,
	})
	// 200 even when Applied is false: the REQUEST succeeded and the answer is
	// "this module is not runtime-switchable, here is why". A 5xx would make an
	// honest refusal indistinguishable from a broken endpoint.
	a.deps.WriteJSON(w, http.StatusOK, change)
}

func (a *API) setLevel(r *http.Request, module Module, level Level, window time.Duration) (LevelChange, error) {
	ctx := r.Context()
	switch module {
	case ModuleAPI:
		if a.deps.SetAPILevel == nil {
			return notSwitchable(module, level, "the API log-level seam is not wired into this build"), nil
		}
		return a.deps.SetAPILevel(level, window), nil
	case ModuleCorrelation:
		if a.deps.CorrLogLevel == nil {
			return notSwitchable(module, level, "no correlation debug-sidecar seam is wired into this build"), nil
		}
		return a.deps.CorrLogLevel(ctx, level, window)
	case ModuleVector:
		if a.deps.VectorLogLevel == nil {
			return notSwitchable(module, level, VectorLevelReason), nil
		}
		return a.deps.VectorLogLevel(ctx, level, window)
	case ModuleRouter:
		return notSwitchable(module, level, VectorLevelReason), nil
	case ModuleIngress:
		return notSwitchable(module, level,
			"syslog-ng's level is set in its config file and applied at (re)start; this deployment has no restart-free way to change it, and restarting the ingest edge during an incident is not an acceptable debug action"), nil
	default:
		return LevelChange{}, fmt.Errorf("module %q has no log-level control", module)
	}
}

// VectorLevelReason is the honest, checked answer for Vector and vector-router:
// Vector reads VECTOR_LOG at process start and its GraphQL API exposes no
// log-level mutation, so there is no runtime switch to call. `vector tap` — the
// per-event stream correlix-debug already uses for the parser and router stages
// — is the substitute, and it needs no level change at all.
const VectorLevelReason = "not runtime-switchable: Vector reads VECTOR_LOG at process start and exposes no log-level mutation on its API. Use the per-event `vector tap` stream instead — correlix-debug already collects it for the parser and router stages"

func notSwitchable(m Module, l Level, reason string) LevelChange {
	return LevelChange{Module: m, Applied: false, Level: l, Reason: reason}
}

// ── GET /api/debug/stage/{stage}?marker= ────────────────────────────────────

// HandleStage serves GET /api/debug/stage/{stage}?marker=…
func (a *API) HandleStage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	stage, err := ParseStage(strings.TrimPrefix(r.URL.Path, "/api/debug/stage/"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	if !IsServerStage(stage) {
		a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf(
			"stage %q is collected on the host by correlix-debug (docker logs / Vector API tap), not by the API", stage))
		return
	}
	marker, err := NormalizeMarker(r.URL.Query().Get("marker"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	kind := KindSyslog
	if raw := r.URL.Query().Get("kind"); raw != "" {
		if kind, err = ParseKind(raw); err != nil {
			a.deps.WriteError(w, http.StatusBadRequest, err)
			return
		}
	}
	tenant, err := effectiveTenant(p, r.URL.Query().Get("tenant"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	entry := a.stage(r, p, stage, kind, marker, tenant)
	a.deps.WriteJSON(w, http.StatusOK, entry)
}

// stage dispatches one server-side stage query.
func (a *API) stage(r *http.Request, p Principal, stage Stage, kind Kind, marker, tenant string) Entry {
	ctx := r.Context()
	switch stage {
	case StageKafka:
		return a.KafkaStage(ctx, kind, marker)
	case StageOpenSearch:
		return a.OpenSearchStage(ctx, p, kind, marker, tenant)
	case StageVictoria:
		return a.VictoriaStage(ctx, kind, marker)
	case StageClickHouse:
		return a.ClickHouseStage(ctx, p, kind, marker)
	case StageCorrelation:
		return a.CorrelationStage(ctx, p, marker)
	case StageAPI:
		return a.APIStage(marker)
	default:
		return notObservable(Entry{Stage: stage, Module: string(stage)},
			"this stage has no server-side evidence source")
	}
}

// ── shared helpers ──────────────────────────────────────────────────────────

func (a *API) audit(r *http.Request, tenant, action string, detail map[string]any) {
	if a.deps.Audit == nil {
		return
	}
	a.deps.Audit(r, tenant, action, detail)
}

// ring records one API-side debug line for a marker (stage 7's evidence).
func (a *API) ring(marker, component, msg string, fields map[string]any) {
	if a.deps.Ring == nil {
		return
	}
	a.deps.Ring.Append(marker, RingLine{
		TS: a.deps.now(), Level: "debug", Component: component, Msg: msg, Fields: fields,
	})
}
