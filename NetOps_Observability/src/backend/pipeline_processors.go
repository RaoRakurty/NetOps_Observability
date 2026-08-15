package backend

// pipeline_processors.go — the Pipeline Processors HTTP surface and the
// config writer that compiles the engine's output into the ingest runtime.
//
// Relocated out of telemetry_enrichment.go (2026-07-31 review B1): that file
// documents the device→tenant CSV export, and ~430 lines of an unrelated
// feature living under its header was a discoverability landmine. The DOMAIN
// logic (model, registries, managed rules, compiler, simulator, versioning)
// lives in the processors subpackage; this file is only the I/O boundary —
// handlers, the file-plane writer, and the store selector.
//
// Routes (all administration:admin, tenant-scoped, cross-tenant id → 404):
//
//	GET|POST         /api/pipeline/processors
//	GET|PUT|DELETE   /api/pipeline/processors/{id}
//	POST             /api/pipeline/processors/preview        — dry run
//	GET              /api/pipeline/processors/catalog        — engine self-description
//	POST             /api/pipeline/processors/clone          — adopt a managed rule
//	GET              /api/pipeline/processors/{id}/versions  — immutable history
//	POST             /api/pipeline/processors/{id}/versions/{n} — roll back

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"io"
	"net/url"
	"netops/backend/internal/audit"
	"netops/backend/internal/httppage"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/quarantine"
	"netops/backend/internal/rbac"
	"netops/backend/internal/secobs"
	"netops/backend/models"
	"netops/backend/processors"
	"netops/backend/sealing"
	"sync/atomic"
)

// ── per-tenant processor rules → router config (item 121) ────────────────────
//
// Same file-plane contract as the enrichment CSV above: the api composes every
// tenant's enabled rules into ONE generated Vector config
// (PROCESSORS_DIR/router/processors.yaml) that the router loads as a second
// --config and hot-reloads via --watch-config. Rules are structured (package
// processors) — user input reaches the file only as escaped string literals.
//
//	GET|POST         /api/pipeline/processors           (administration:admin)
//	GET|PUT|DELETE   /api/pipeline/processors/{id}
//	POST             /api/pipeline/processors/preview   (dry-run on a sample event)

const processorsFileName = "processors.yaml"

// newProcessorStore selects pg under the Postgres backend, else file.
func newProcessorStore() processors.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return processors.NewPGStore(ps.DB())
	}
	return processors.NewFileStore(envOr("PROCESSORS_RULES_FILE", "/data/pipeline_processors.json"))
}

// writeProcessorsConfig regenerates the router config from every tenant's
// enabled rules. Content-compared before writing so --watch-config never sees
// a phantom change; atomic temp+rename like every file on this plane.
func (s *server) writeProcessorsConfig(ctx context.Context) error {
	dir := os.Getenv("PROCESSORS_DIR")
	if dir == "" || s.processors == nil {
		return nil
	}
	rules, err := s.processors.AllEnabled(ctx)
	if err != nil {
		return err
	}
	content, err := processors.GenerateRouterConfig(rules)
	if err != nil {
		// F-11 (INV-F11-01/06, review fix 2026-08-14): generation fails when the
		// quarantine stage cannot be rendered while sealing is configured.
		// Returning here — BEFORE any write — keeps the last-good config live at
		// the router (its quarantine stage intact), instead of hot-loading a
		// config that lets registry-MISS events flow plaintext with no exit-78
		// backstop. Loud and structured (§10): this line rides the applogs
		// pipeline into OpenSearch, alongside the callers' stdout log; the 60s
		// ticker and the next mutation both retry, so a transient custody
		// failure self-heals.
		logError("processors", "router config generation FAILED — keeping the last-good config (a config without the quarantine stage would store unattributable events in plaintext)",
			map[string]any{"error": err.Error()})
		return fmt.Errorf("generate router config: %w", err)
	}
	routerDir := filepath.Join(dir, "router")
	target := filepath.Join(routerDir, processorsFileName)
	// #nosec G304 -- the path is $PROCESSORS_DIR (operator-set env, from compose)
	// joined with a package CONSTANT filename. No request data, no tenant data
	// and no processor field reaches it, so there is no traversal surface; the
	// read exists only to skip rewriting an unchanged file.
	if prev, err := os.ReadFile(target); err == nil && string(prev) == content {
		return nil // unchanged — don't touch the watched file
	}
	if err := os.MkdirAll(routerDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(routerDir, ".processors-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Vector runs as a different uid — same 0644 rationale as the CSV above.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	log.Printf("processors: wrote router config (%d enabled rules) to %s", len(rules), target)
	return nil
}

// processorsKick is the coalescing signal from a mutation to the single config
// writer. Capacity 1 by design: N concurrent mutations collapse into ONE
// regeneration that reads the latest state.
//
// The previous shape — a detached goroutine per mutation on
// context.Background() — was unbounded (§9), outlived shutdown, and could
// interleave: two regens racing meant an OLDER AllEnabled snapshot could win
// the final rename and leave a stale config live until the next 60s tick.
var processorsKick = make(chan struct{}, 1)

// regenProcessorsAsync asks the writer to regenerate. Never blocks a request.
func (s *server) regenProcessorsAsync() {
	select {
	case processorsKick <- struct{}{}:
	default: // a regeneration is already pending; it will read the latest state
	}
}

// startProcessorsConfigWriter is the periodic writer. No-op unless
// PROCESSORS_DIR is set (file/dev builds without the shared volume).
func (s *server) startProcessorsConfigWriter(ctx context.Context) {
	if os.Getenv("PROCESSORS_DIR") == "" || s.processors == nil {
		return
	}
	interval := 60 * time.Second
	if v := os.Getenv("PROCESSORS_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	go func() {
		wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if err := s.writeProcessorsConfig(wctx); err != nil {
			log.Printf("processors: initial write: %v", err)
		}
		cancel()
		t := time.NewTicker(interval)
		defer t.Stop()
		write := func(why string) {
			wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if err := s.writeProcessorsConfig(wctx); err != nil {
				log.Printf("processors: %s write: %v", why, err)
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-processorsKick: // a mutation landed — regenerate now
				write("mutation")
			case <-t.C:
				write("periodic")
			}
		}
	}()
}

// decodeProcessorRule reads and validates an operator payload; `enabled`
// defaults to TRUE when omitted (a rule that silently did nothing would be
// the worst failure mode — same contract as maintenance windows).
func decodeProcessorRule(w http.ResponseWriter, r *http.Request) (processors.Processor, bool) {
	// ONE decode: the embedded Processor carries every field, and the pointer
	// Enabled distinguishes "omitted" (default true — a processor that silently
	// did nothing would be the worst default) from an explicit false.
	var body struct {
		processors.Processor
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return processors.Processor{}, false
	}
	in := body.Processor
	in.Enabled = body.Enabled == nil || *body.Enabled
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return processors.Processor{}, false
	}
	return in, true
}

func (s *server) handleProcessors(w http.ResponseWriter, r *http.Request) {
	if s.processors == nil {
		writeError(w, http.StatusNotImplemented, errors.New("processor store unavailable"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		out, err := s.processors.List(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": out, "count": len(out)})
	case http.MethodPost:
		in, ok := decodeProcessorRule(w, r)
		if !ok {
			return
		}
		if !cross {
			in.TenantID = tenant // §3a.2: owner from the token, never the body
		}
		in.CreatedBy = claims.Sub
		out, err := s.processors.Create(r.Context(), tenant, cross, in)
		if errors.Is(err, processors.ErrLimit) {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.regenProcessorsAsync()
		writeJSON(w, http.StatusCreated, out)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// processorPreviewRequest is the dry-run body: a sample event, the lane, and
// optionally the DRAFT being edited.
//
// The draft matters: without it the preview only ran SAVED processors, so an
// operator building a rule in the wizard pressed "preview" and saw the before
// and after panes identical — the rule they were writing was not in the chain
// yet. Previewing a rule you cannot see the effect of is not a preview.
type processorPreviewRequest struct {
	Lane  string         `json:"lane"`
	Event map[string]any `json:"event"`
	// Draft is an unsaved processor to append to the chain for this run only.
	// It is validated exactly like a save, and never persisted.
	Draft *processors.Processor `json:"processor,omitempty"`
}

// handleProcessorByID routes the per-processor surface. Each sub-route is its
// own handler (review B2 — this was a 240-line string-matching switch that
// repeated the auth + tenant derivation in five branches).
func (s *server) handleProcessorByID(w http.ResponseWriter, r *http.Request) {
	if s.processors == nil {
		writeError(w, http.StatusNotImplemented, errors.New("processor store unavailable"))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/pipeline/processors/")
	switch rest {
	case "preview":
		s.handleProcessorPreview(w, r)
	case "catalog":
		s.handleProcessorCatalog(w, r)
	case "clone":
		s.handleProcessorClone(w, r)
	case "unseal":
		s.handleProcessorUnseal(w, r)
	case "unseal/audit":
		s.handleSealAccessAudit(w, r)
	case "seal/rotate":
		s.handleSealRotate(w, r)
	default:
		if id, tail, isSub := strings.Cut(rest, "/"); isSub && strings.HasPrefix(tail, "versions") {
			s.handleProcessorVersions(w, r, id, tail)
			return
		}
		s.handleProcessorCRUD(w, r, rest)
	}
}

// handleProcessorPreview — POST …/preview: run the caller's OWN saved chain
// against a sample event. The event is data: echoed back shaped, never stored
// or executed.
func (s *server) handleProcessorPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	var req processorPreviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	req.Lane = strings.ToLower(strings.TrimSpace(req.Lane))
	if !processors.Lanes[req.Lane] {
		writeError(w, http.StatusBadRequest, fmt.Errorf("lane must be one of %s", strings.Join(processors.LaneOrder, ", ")))
		return
	}
	if req.Event == nil {
		writeError(w, http.StatusBadRequest, errors.New("event is required"))
		return
	}
	rules, err := s.processors.List(r.Context(), tenant, cross)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Append the unsaved DRAFT so the wizard shows what the rule being written
	// will actually do. Without it the preview ran only SAVED processors, so an
	// operator building a rule pressed "preview" and saw before and after
	// identical — the rule they were writing was not in the chain yet. A
	// preview whose effect you cannot see is not a preview.
	if req.Draft != nil {
		draft := *req.Draft
		draft.ID = "draft"
		draft.Name = strings.TrimSpace(draft.Name)
		if draft.Name == "" {
			draft.Name = "(unsaved draft)"
		}
		draft.Lane, draft.Enabled = req.Lane, true
		// The draft belongs to the caller — never to whatever a payload claims.
		if !cross {
			draft.TenantID = tenant
		}
		if err := draft.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("draft: %w", err))
			return
		}
		if draft.Order == 0 {
			draft.Order = processors.MaxOrder // runs last, like a new processor
		}
		rules = append(rules, draft)
	}
	// The simulation runs under the CALLER's tenant: stamp the sample the
	// way the router's enrichment would, so the tenant guard behaves.
	if !cross {
		req.Event["tenant_id"] = tenant
	}
	simTenant := tenant
	if cross {
		// Typed extraction: fmt.Sprintf on a missing key yields the literal
		// "<nil>", which silently matched nothing and made a platform owner
		// conclude the rules were broken (review A5).
		ev, _ := req.Event["tenant_id"].(string)
		simTenant = strings.ToLower(strings.TrimSpace(ev))
	}
	// The preview runs the SAME engine the compiler emits from
	// (processors.SimulateChain) — never a parallel preview implementation.
	// Snapshot BEFORE the tenant stamp below so "original" is genuinely the
	// caller's event, not a mutated copy.
	original := map[string]any{}
	for k, v := range req.Event {
		original[k] = v
	}
	res := processors.SimulateChain(rules, req.Lane, simTenant, req.Event)
	writeJSON(w, http.StatusOK, map[string]any{
		"original": original,
		"event":    res.Event,
		"applied":  res.Applied,
		"dropped":  res.Dropped,
	})
}

// handleProcessorCatalog — GET …/catalog: the engine describes ITSELF
// (actions, matchers, managed rules, lanes). The wizard renders from this, so a
// newly-registered plugin appears in the UI with no frontend change.
func (s *server) handleProcessorCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"actions":       processors.ActionCatalog(),
		"matchers":      processors.MatcherCatalog(),
		"managed_rules": processors.ManagedRules(),
		"lanes":         processors.LaneOrder,
		// Sealing is the one action that can be REGISTERED but unavailable (it
		// needs key custody). The wizard reads this to disable the option with a
		// reason, instead of offering a choice that fails on save.
		"seal_available": processors.SealAvailable(),
		"seal_presets":   processors.SealPresets,
	})
}

// handleProcessorClone — POST …/clone: adopt a managed rule as an editable,
// tenant-owned processor. Same engine, same storage; only provenance differs.
func (s *server) handleProcessorClone(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var req struct {
		ManagedRuleID string `json:"managed_rule_id"`
		Lane          string `json:"lane"`
		Field         string `json:"field"`
		Order         int    `json:"order"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return
	}
	in, ok := processors.CloneManagedRule(req.ManagedRuleID, strings.ToLower(strings.TrimSpace(req.Lane)), strings.TrimSpace(req.Field))
	if !ok {
		writeError(w, http.StatusBadRequest, errors.New("unknown managed rule"))
		return
	}
	in.Order = req.Order
	tenant, cross := principalTenant(claims)
	if !cross {
		in.TenantID = tenant
	}
	in.CreatedBy = claims.Sub
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	out, err := s.processors.Create(r.Context(), tenant, cross, in)
	if errors.Is(err, processors.ErrLimit) {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.regenProcessorsAsync()
	writeJSON(w, http.StatusCreated, out)
}

// handleProcessorVersions — GET …/{id}/versions (immutable history) and
// POST …/{id}/versions/{n} (roll back; recorded as a NEW version).
func (s *server) handleProcessorVersions(w http.ResponseWriter, r *http.Request, id, tail string) {
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid processor id"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	if r.Method == http.MethodGet && tail == "versions" {
		vs, found, err := s.processors.ListVersions(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"versions": vs, "count": len(vs)})
		return
	}
	if r.Method == http.MethodPost && strings.HasPrefix(tail, "versions/") {
		n, err := strconv.Atoi(strings.TrimPrefix(tail, "versions/"))
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, errors.New("version must be a positive integer"))
			return
		}
		out, found, err := s.processors.Rollback(r.Context(), tenant, cross, id, n, claims.Sub)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		s.regenProcessorsAsync()
		writeJSON(w, http.StatusOK, out)
		return
	}
	w.Header().Set("Allow", "GET, POST")
	writeError(w, http.StatusMethodNotAllowed, errors.New("GET versions or POST versions/{n}"))
}

// handleProcessorCRUD — GET | PUT | DELETE …/{id}.
func (s *server) handleProcessorCRUD(w http.ResponseWriter, r *http.Request, rest string) {

	if !isUUIDToken(rest) {
		writeError(w, http.StatusBadRequest, errors.New("invalid rule id"))
		return
	}
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		rule, found, err := s.processors.Get(r.Context(), tenant, cross, rest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r) // cross-tenant id indistinguishable from absent
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case http.MethodPut:
		in, ok := decodeProcessorRule(w, r)
		if !ok {
			return
		}
		out, found, err := s.processors.Update(r.Context(), tenant, cross, rest, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		s.regenProcessorsAsync()
		writeJSON(w, http.StatusOK, out)
	case http.MethodDelete:
		found, err := s.processors.Delete(r.Context(), tenant, cross, rest)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		s.regenProcessorsAsync()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": rest})
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// ── Sealed Fields: the reveal path ──────────────────────────────────────────

// maxUnsealBody bounds the request. A sealed token is a few hundred bytes; this
// is generous and still refuses an unbounded read (§9).
const maxUnsealBody = 16 << 10

// sealMetrics counts reveal attempts by outcome. Deliberately NO per-value or
// per-field label: a metric series named after the data it protects is a
// disclosure channel that survives in the TSDB long after the audit entry ages
// out.
type sealMetrics struct {
	granted   atomic.Int64
	forbidden atomic.Int64
	notFound  atomic.Int64 // token unreadable: tampered, malformed, wrong tenant
	keyGone   atomic.Int64 // key version retired or custody unavailable
}

func (m *sealMetrics) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP netops_unmask_requests_total Sealed-value reveal attempts, by outcome.\n")
	fmt.Fprintf(w, "# TYPE netops_unmask_requests_total counter\n")
	fmt.Fprintf(w, "netops_unmask_requests_total{outcome=%q} %d\n", "granted", m.granted.Load())
	fmt.Fprintf(w, "netops_unmask_requests_total{outcome=%q} %d\n", "forbidden", m.forbidden.Load())
	fmt.Fprintf(w, "netops_unmask_requests_total{outcome=%q} %d\n", "unreadable", m.notFound.Load())
	fmt.Fprintf(w, "netops_unmask_requests_total{outcome=%q} %d\n", "key_unavailable", m.keyGone.Load())
}

type unsealRequest struct {
	Value string `json:"value"`
	// Optional narrowing hints. When supplied they are tried FIRST; when absent
	// (the common case — an operator pasting a token out of a log line) the
	// server searches this tenant's seal processors.
	ProcessorID string `json:"processor_id,omitempty"`
	Field       string `json:"field,omitempty"`
	DataType    string `json:"data_type,omitempty"`
	// Reason is the operator's justification. Recorded in the audit trail; this
	// is a compliance surface, and "who revealed a card number and why" is the
	// question it has to answer.
	Reason string `json:"reason,omitempty"`
}

type unsealResponse struct {
	Value      string `json:"value"`
	Field      string `json:"field,omitempty"`
	DataType   string `json:"data_type,omitempty"`
	Processor  string `json:"processor_id,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
}

// handleProcessorUnseal reveals one sealed value.
func (s *server) handleProcessorUnseal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	if s.sealProvider == nil {
		writeError(w, http.StatusNotImplemented, errors.New("sealed fields are not enabled on this deployment"))
		return
	}
	// sensitive_data:admin — NOT administration:admin. Sealing is a per-tenant
	// data capability, so it gets its own module: an infrastructure admin who
	// should never read card numbers does not acquire the ability by being an
	// admin of something else.
	claims, ok := s.requirePerm(w, r, rbac.ModuleSensitiveData, rbac.LevelAdmin)
	if !ok {
		s.sealMetrics.forbidden.Add(1)
		// The audit middleware already records the 403. Nothing more is added
		// here: a denied caller must not learn whether the token was even valid.
		return
	}

	var req unsealRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxUnsealBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	req.Value = strings.TrimSpace(req.Value)
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, errors.New("value is required"))
		return
	}
	if !sealing.IsSealed(req.Value) {
		writeError(w, http.StatusBadRequest, errors.New("value is not a sealed token"))
		return
	}

	tenant, cross := principalTenant(claims)
	// The token names its own tenant. Refuse a cross-tenant reveal BEFORE
	// touching key material, and refuse it as 404 — confirming that another
	// tenant's token exists is itself a disclosure (§3a).
	owner, okOwner := sealing.TenantOf(req.Value)
	if !okOwner {
		s.sealMetrics.notFound.Add(1)
		writeError(w, http.StatusBadRequest, errors.New("value is not a readable sealed token"))
		return
	}
	if !cross && !strings.EqualFold(owner, tenant) {
		s.sealMetrics.notFound.Add(1)
		s.auditUnseal(claims, req, owner, 0, "denied_cross_tenant")
		writeError(w, http.StatusNotFound, errors.New("no such sealed value"))
		return
	}

	plaintext, ctx, err := s.unsealWithKnownContexts(r, owner, req)
	if err != nil {
		switch {
		case errors.Is(err, sealing.ErrKeyUnavailable):
			s.sealMetrics.keyGone.Add(1)
			s.auditUnseal(claims, req, owner, 0, "key_unavailable")
			// 410: the value is genuinely gone, not merely refused. An operator
			// needs to tell "I may not" from "nobody can, ever again".
			writeError(w, http.StatusGone, errors.New("the key that sealed this value is no longer available"))
		default:
			s.sealMetrics.notFound.Add(1)
			s.auditUnseal(claims, req, owner, 0, "unreadable")
			writeError(w, http.StatusBadRequest, errors.New("this value could not be verified — it may have been altered, or it was sealed by a processor that no longer exists"))
		}
		return
	}

	version, _ := sealing.KeyVersionOf(req.Value)
	// Audit-BEFORE-commit (M19): the grant is recorded durably FIRST; if the
	// trail refuses the record, the plaintext is withheld with a 5xx. A reveal
	// the trail never witnessed must not happen — this is the one compliance
	// surface whose whole value is "no unrecorded disclosure".
	if err := s.auditUnsealStrict(claims, req, owner, version, "granted"); err != nil {
		logError("sealing", "reveal refused: audit trail could not record the grant", map[string]any{"error": err.Error()})
		writeError(w, http.StatusServiceUnavailable, errors.New("the audit trail could not record this reveal — nothing was disclosed; retry once the trail is healthy"))
		return
	}
	s.sealMetrics.granted.Add(1)

	writeJSON(w, http.StatusOK, unsealResponse{
		Value:      plaintext,
		Field:      ctx.Field,
		DataType:   ctx.DataType,
		Processor:  ctx.ProcessorID,
		KeyVersion: version,
	})
}

// unsealWithKnownContexts tries the caller's hint first, then every seal
// processor this tenant owns, and returns the first context whose MAC verifies.
//
// It reports ErrKeyUnavailable distinctly: if the key is gone, no candidate can
// possibly verify, so the loop stops rather than grinding through every
// processor to reach the same conclusion.
func (s *server) unsealWithKnownContexts(r *http.Request, tenant string, req unsealRequest) (string, sealing.Context, error) {
	candidates := make([]sealing.Context, 0, 8)
	if req.ProcessorID != "" && req.Field != "" {
		candidates = append(candidates, sealing.Context{
			Tenant: tenant, ProcessorID: req.ProcessorID, Field: req.Field,
			DataType: req.DataType,
		})
	}
	for _, p := range s.sealProcessorsFor(r.Context(), tenant) {
		candidates = append(candidates, sealing.Context{
			Tenant: tenant, ProcessorID: p.ID, Field: p.Field,
			DataType: p.DataTypeOrField(),
		})
	}
	if len(candidates) == 0 {
		return "", sealing.Context{}, sealing.ErrWrongContext
	}

	var lastErr = sealing.ErrWrongContext
	for _, c := range candidates {
		plaintext, err := s.sealProvider.Unseal(r.Context(), c, req.Value)
		if err == nil {
			return plaintext, c, nil
		}
		if errors.Is(err, sealing.ErrKeyUnavailable) {
			return "", sealing.Context{}, err // no candidate can succeed
		}
		lastErr = err
	}
	return "", sealing.Context{}, lastErr
}

// sealProcessorsFor lists this tenant's seal processors, including disabled
// ones: a rule can be turned off long after it sealed values that still need
// revealing.
func (s *server) sealProcessorsFor(ctx context.Context, tenant string) []processors.Processor {
	if s.processors == nil {
		return nil
	}
	// cross=false: the reveal path resolves contexts for ONE tenant only. A
	// cross-tenant listing here would let a platform owner's search silently
	// pull another tenant's processor definitions into the candidate set.
	all, err := s.processors.List(ctx, tenant, false)
	if err != nil {
		return nil
	}
	out := make([]processors.Processor, 0, len(all))
	for _, p := range all {
		if p.Type == processors.TypeSeal {
			out = append(out, p)
		}
	}
	return out
}

// auditUnseal records the attempt best-effort (denial paths: the caller got
// nothing, so a lost record is a gap, not an unwitnessed disclosure). The
// plaintext, and anything derived from it, is deliberately absent — an audit
// trail that leaks what it audits is worse than none, because it concentrates
// every revealed secret in one admin-readable place.
func (s *server) auditUnseal(claims jwtClaims, req unsealRequest, owner string, version int, outcome string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(s.unsealAuditEvent(claims, req, owner, version, outcome))
}

// auditUnsealStrict is the audit-BEFORE-commit variant for the GRANTED path
// (M19): the reveal is the one route that turns protected data back into
// plaintext, so "who read what and why" must be durably recorded before the
// plaintext leaves the process. A failed (or absent) trail returns an error and
// the caller withholds the plaintext — never the other way around.
func (s *server) auditUnsealStrict(claims jwtClaims, req unsealRequest, owner string, version int, outcome string) error {
	if s.audit == nil {
		return errors.New("audit trail is not configured")
	}
	return s.audit.RecordStrict(s.unsealAuditEvent(claims, req, owner, version, outcome))
}

func (s *server) unsealAuditEvent(claims jwtClaims, req unsealRequest, owner string, version int, outcome string) AuditEvent {
	tenant, cross := principalTenant(claims)
	detail := map[string]any{
		"outcome":       outcome,
		"value_tenant":  owner,
		"data_type":     req.DataType,
		"field":         req.Field,
		"processor_id":  req.ProcessorID,
		"reason":        truncateReason(req.Reason),
		"actor_tenant":  tenant,
		"cross_tenant":  cross,
		"key_version":   version,
		"token_preview": sealing.TokenFingerprint(req.Value),
	}
	status := http.StatusOK
	decision := "allow"
	if outcome != "granted" {
		status, decision = http.StatusForbidden, "deny"
	}
	return AuditEvent{
		Actor:    claims.Sub,
		Tenant:   tenant,
		Cross:    cross,
		Method:   http.MethodPost,
		Path:     unsealRoutePath,
		Status:   status,
		Decision: decision,
		Detail:   detail,
	}
}

// maxReasonLen bounds the operator's justification so a caller cannot use the
// audit trail as unbounded storage.
const maxReasonLen = 512

func truncateReason(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxReasonLen {
		return s[:maxReasonLen]
	}
	return s
}

// internalStackCaller reports whether a request carries the stack-internal
// credential (the INGEST_USER/INGEST_TOKEN pair compose gives every in-stack
// client). It is the gate on edge key delivery.
//
// Fail-closed by construction: an unset INGEST_TOKEN makes this return false
// for every caller, so a misconfigured stack serves NO key material rather than
// serving it to anyone who can reach the port.
func (s *server) internalStackCaller(r *http.Request) bool {
	want := os.Getenv("INGEST_TOKEN")
	if want == "" {
		return false
	}
	user, token, ok := r.BasicAuth()
	if !ok {
		return false
	}
	wantUser := os.Getenv("INGEST_USER")
	if wantUser == "" {
		wantUser = "netops-ingest"
	}
	// Constant time on BOTH components: a timing oracle on the username is a
	// slower path to the same place.
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	tokenOK := subtle.ConstantTimeCompare([]byte(token), []byte(want)) == 1
	return userOK && tokenOK
}

// handleSealAccessAudit — GET /api/pipeline/processors/unseal/audit
//
// The compliance view: who revealed sensitive data, when, for what stated
// reason, and whether they were allowed to. It is the reveal endpoint's
// counterpart — the reason auditing a reveal is worth anything is that someone
// can read the result back.
//
// Server-side filtered to the unseal route. Filtering client-side over a capped
// page would show an EMPTY list whenever reveals sit below the newest N audit
// rows, and a compliance surface that silently reports "nobody read anything"
// is precisely the failure this page cannot have.
func (s *server) handleSealAccessAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	// Reading WHO revealed data is itself sensitive: it names the values that
	// were interesting enough to look at. Same gate as revealing.
	claims, ok := s.requirePerm(w, r, rbac.ModuleSensitiveData, rbac.LevelAdmin)
	if !ok {
		return
	}
	if s.audit == nil {
		writeError(w, http.StatusNotImplemented, errors.New("audit store unavailable"))
		return
	}
	page, err := httppage.Parse(r, audit.DefaultLimit, audit.MaxQueryLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q := auditQuery{Limit: page.Limit, Offset: page.Offset, Path: unsealRoutePath}
	events, err := s.auditScopedList(claims, q)
	if err != nil {
		// An ERROR is not an empty trail. Surfacing it as 200 [] would read as
		// "no one has revealed anything", which is the most dangerous possible
		// lie for this particular page (§10).
		writeError(w, http.StatusBadGateway, fmt.Errorf("audit trail unavailable: %w", err))
		return
	}
	total := s.auditScopedCount(claims, q)
	// Same pagination contract as every other listing surface (headers carry the
	// TRUE total, pinned by internal/httppage/contract_test.go).
	httppage.Write(w, "events", events, page, len(events), total)
}

// handleSealRotate — POST /api/pipeline/processors/seal/rotate
//
// Advances the caller's tenant to a new sealing key version. Values already
// sealed are NOT re-encrypted and keep opening: each names the version that
// sealed it. That is the only model that works at log scale, where sealed
// values live in immutable OpenSearch and ClickHouse data across the whole
// retention window.
func (s *server) handleSealRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if s.sealProvider == nil {
		writeError(w, http.StatusNotImplemented, errors.New("sealed fields are not enabled on this deployment"))
		return
	}
	claims, ok := s.requirePerm(w, r, rbac.ModuleSensitiveData, rbac.LevelAdmin)
	if !ok {
		return
	}
	tenant, _ := principalTenant(claims)
	if tenant == "" {
		writeError(w, http.StatusBadRequest, errors.New("a tenant-scoped principal is required"))
		return
	}
	version, err := s.sealProvider.Rotate(r.Context(), tenant)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("rotate sealing key: %w", err))
		return
	}
	// The ROUTER still holds the previous key: Vector resolves secrets at config
	// load. Say so rather than letting an operator believe rotation took effect
	// at the edge the moment this returned.
	s.regenProcessorsAsync()
	writeJSON(w, http.StatusOK, map[string]any{
		"key_version": version,
		"note":        "New values seal under this version once the router reloads its config. Values sealed under earlier versions remain readable.",
	})
}

// unsealRoutePath is the audited route, named once so the recorder and the
// reader cannot drift.
const unsealRoutePath = "/api/pipeline/processors/unseal"

// sealingEdgeIdentity is the ONLY workload identity the edge-key endpoint
// accepts over mTLS (SEC-018.1): the vector-router, whose exec secret
// backend is the single legitimate consumer of derived tenant keys.
// Env-overridable for split trust domains; the default matches the
// registry's SPIFFE shape.
func sealingEdgeIdentity() string {
	if v := strings.TrimSpace(os.Getenv("SEALING_CLIENT_URI")); v != "" {
		return v
	}
	td := os.Getenv("TLS_TRUST_DOMAIN")
	if td == "" {
		td = "netops"
	}
	return "spiffe://" + td + "/ns/default/sa/vector-router"
}

// sealingEdgeCaller — SEC-018.1's gate on edge key delivery, replacing the
// shared ingest token that six other clients hold ("the sharpest one",
// HLD §1.1). Three regimes, fail-closed in every one:
//
//   - plaintext deployment (r.TLS == nil): the stack-internal token, exactly
//     as before — the documented baseline is unchanged.
//   - TLS deployment: ONLY the vector-router's peer certificate URI. A
//     stolen INGEST_TOKEN can no longer fetch any tenant's sealing key.
//   - TLS deployment mid-migration (SEALING_ACCEPT_TOKEN=true): token OR
//     identity — the dual-accept window the rollout plan requires; close it
//     by unsetting the flag.
func (s *server) sealingEdgeCaller(r *http.Request) bool {
	if r.TLS == nil {
		return s.internalStackCaller(r)
	}
	if len(r.TLS.PeerCertificates) > 0 {
		want := sealingEdgeIdentity()
		for _, uri := range r.TLS.PeerCertificates[0].URIs {
			if uri.String() == want {
				return true
			}
		}
	}
	if os.Getenv("SEALING_ACCEPT_TOKEN") == "true" {
		return s.internalStackCaller(r)
	}
	return false
}

// edgeKeyScopeResolver is the edge-key endpoint's scope guard: it maps the
// UNTRUSTED `?tenant=` string to the canonical key scope, or refuses.
//
//   - a reserved engine scope (processors.IsReservedSealScope — today the
//     quarantine scope the router config references as SECRET[cxseal.quarantine])
//     is served verbatim; it is not a tenant and must not be resolved as one;
//   - a real tenant (id OR slug, any case) resolves to its canonical ID, so the
//     custody store holds exactly one DEK per tenant — a caller cannot mint one
//     row per spelling (`Acme`, `aCme`, `t_<id>` …);
//   - anything else is refused (uniform 404 upstream: no enumeration).
func (s *server) edgeKeyScopeResolver() func(string) (string, bool) {
	return func(scope string) (string, bool) {
		if processors.IsReservedSealScope(scope) {
			return scope, true
		}
		if s.tenants == nil {
			return "", false
		}
		t, ok := s.tenants.Resolve(scope)
		if !ok {
			return "", false
		}
		return t.ID, true
	}
}

// sealingEdgePeer names the caller for the key-fetch audit line: the peer
// certificate's SPIFFE URI when present, else the shared-token label. Never
// key material, never a token value.
func sealingEdgePeer(r *http.Request) string {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
		return r.TLS.PeerCertificates[0].URIs[0].String()
	}
	return "stack-internal-token"
}

// ── F-11 seal-or-quarantine: the operator workflow (design doc D5) ──────────
//
// THIN GLUE ONLY (root file-count ratchet): the logic lives in
// internal/quarantine; these handlers wire the injected effects — the
// openSearch fetch, the seal provider, the bus producer and the audit trail —
// and enforce the gates. Both routes are ledger category `platform`
// (route_isolation_test.go): the quarantine holds OTHER tenants'
// unattributable data by definition, so no tenant principal may see it.

const (
	quarantineReattrRoutePath = "/api/quarantine/reattribute"
	// quarantineSearchPath targets every daily quarantine index; a missing
	// index resolves to zero hits (allow_no_indices), never an error.
	quarantineSearchPath = "/netops-quarantine-*/_search"
	// quarantineBatchLimit bounds one re-attribution call; the response
	// reports the remainder so the operator repeats until zero.
	quarantineBatchLimit = 500
	quarantineListLimit  = 50 // default page size for the metadata list
)

// handleQuarantineList — GET /api/quarantine (requirePlatformAdmin): the
// metadata listing plus a depth/age summary. NEVER the sealed payload: the
// _source projection excludes it AND quarantine.Doc cannot serialize it.
func (s *server) handleQuarantineList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET required"))
		return
	}
	// The sealed-fields idiom (handleProcessorUnseal): without sealing custody
	// there is no quarantine stage — say so, not 404 or an empty list.
	if s.sealProvider == nil {
		writeError(w, http.StatusNotImplemented, errors.New("sealed fields are not enabled on this deployment"))
		return
	}
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}
	if err := httppage.RejectUnknownQuery(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	page, err := httppage.Parse(r, quarantineListLimit, quarantineBatchLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	resp, err := openSearch(http.MethodPost, quarantineSearchPath, quarantine.ListQuery(page.Offset, page.Limit))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable,
			errors.New("quarantine index is unreachable — this is NOT an empty quarantine; retry"))
		return
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeError(w, http.StatusServiceUnavailable,
			fmt.Errorf("quarantine index read failed (opensearch status %d) — this is NOT an empty quarantine; retry", resp.StatusCode))
		return
	}
	docs, total, oldest, err := quarantine.ParseSearch(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	httppage.WriteHeaders(w, page, len(docs), int(total))
	summary := map[string]any{"total": total, "oldest_received_at": nil}
	if oldest != "" {
		summary["oldest_received_at"] = oldest
	}
	writeJSON(w, http.StatusOK, map[string]any{"quarantine": docs, "summary": summary})
}

// isHex64 reports whether s is a well-formed sha256 hex digest (the only
// accepted identity reference — validate at the boundary, §3).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// quarantineIdentityRows projects the live inventory onto the SAME identity
// strings the ingest tier hashes (device name + management address — the
// buildEnrichmentRows identities), each with its owning tenant.
func quarantineIdentityRows(devices []models.Device) []quarantine.IdentityRow {
	rows := make([]quarantine.IdentityRow, 0, len(devices)*2)
	for _, d := range devices {
		t := deviceTenant(d)
		if d.Name != "" {
			rows = append(rows, quarantine.IdentityRow{Identity: d.Name, Tenant: t})
		}
		if d.Address != "" {
			rows = append(rows, quarantine.IdentityRow{Identity: d.Address, Tenant: t})
		}
	}
	return rows
}

// handleQuarantineReattribute — POST /api/quarantine/reattribute: unseal every
// envelope whose identity now resolves (authoritatively, via the live
// inventory) to exactly one tenant, re-inject the original events onto their
// lanes' bus topics, then tombstone the envelopes.
//
// Gates, in order: sensitive_data:admin FIRST — it is the unseal-equivalent
// capability and the deliberate second key next to the platform gate (today
// every platform owner is a super-admin and so holds it; the explicit check
// pins the policy against a future role-model change) — then the platform
// gate itself.
//
// Replay-safe end to end, two contracts by lane: on the OS-canonical lanes
// (syslog, snmptrap) re-runs upsert the same cx_event_id (`id_key` on the OS
// event sinks); on the flows lane the canonical store is ClickHouse (plain
// MergeTree — no id dedup), so the quarantine package enforces at-most-once
// produce via a CAS claim on the envelope doc (quarantine.Restore) wired to
// the Claim/Unclaim deps below. Either way, calling this twice can never
// duplicate tenant data — proven by TestQuarantineReattributeHappyPathAndReplay
// and TestQuarantineReattributeFlowsReplayGuard.
func (s *server) handleQuarantineReattribute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST required"))
		return
	}
	if s.sealProvider == nil {
		writeError(w, http.StatusNotImplemented, errors.New("sealed fields are not enabled on this deployment"))
		return
	}
	claims, ok := s.requirePerm(w, r, rbac.ModuleSensitiveData, rbac.LevelAdmin)
	if !ok {
		return
	}
	if _, ok := s.requirePlatformAdmin(w, r); !ok {
		return
	}

	var req struct {
		IdentitySha string `json:"identity_sha"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxUnsealBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	sha := strings.ToLower(strings.TrimSpace(req.IdentitySha))
	if !isHex64(sha) {
		writeError(w, http.StatusBadRequest, errors.New("identity_sha must be a 64-character sha256 hex digest"))
		return
	}

	// Resolve AUTHORITATIVELY against the live inventory. The caller names an
	// identity hash, never a tenant — zero matches, platform-only and
	// ambiguous identities are all 409s that name the fix.
	tenant, matched, err := quarantine.ResolveIdentity(quarantineIdentityRows(s.discovery.Devices()), sha)
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	resp, err := openSearch(http.MethodPost, quarantineSearchPath, quarantine.ShaQuery(sha, quarantineBatchLimit))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("quarantine index is unreachable; retry"))
		return
	}
	defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		writeError(w, http.StatusServiceUnavailable,
			fmt.Errorf("quarantine search failed (opensearch status %d); retry", resp.StatusCode))
		return
	}
	docs, total, _, err := quarantine.ParseSearch(resp.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}

	deps := quarantine.RestoreDeps{
		Unseal: func(ctx context.Context, token string) (string, error) {
			return s.sealProvider.Unseal(ctx, quarantine.SealContext(), token)
		},
		Produce: func(ctx context.Context, topic, tenant string, event map[string]any) error {
			n, err := produceJSON(ctx, topic, []proxyRecord{{Key: tenant, Value: event}})
			if err != nil {
				return err
			}
			// produceJSON is a silent no-op when the bus bridge is disabled
			// (BUS_BRIDGE_URL=""). Acceptable for best-effort feeds; here it
			// would tombstone events that were never re-injected — data loss.
			if n != 1 {
				return errors.New("bus bridge disabled — restore refused")
			}
			return nil
		},
		Delete: func(ctx context.Context, index, id string) error {
			err := s.osJSON(ctx, http.MethodDelete, "/"+index+"/_doc/"+url.PathEscape(id), nil, nil)
			if err != nil {
				// §10 no silent failures: the count reaches the response, the
				// specifics land here. The leftover doc is noise, not
				// duplication: OS lanes upsert by id_key, the flows lane is
				// claim-stamped so a re-run refuses the replay.
				logError("quarantine", "tombstone delete failed after successful re-injection",
					map[string]any{"index": index, "doc": id, "error": err.Error()})
			}
			return err
		},
		// Claim is the flows replay guard (quarantine.laneReplayGuarded): a CAS
		// update stamping cx_restored_at, conditioned on the doc's search-time
		// seq_no/primary_term so exactly one concurrent restore wins each
		// envelope. 409 = lost the race (or the doc changed) → ErrClaimConflict.
		Claim: func(ctx context.Context, index, id string, seqNo, primaryTerm int64) error {
			path := "/" + index + "/_update/" + url.PathEscape(id) +
				"?if_seq_no=" + strconv.FormatInt(seqNo, 10) +
				"&if_primary_term=" + strconv.FormatInt(primaryTerm, 10)
			resp, err := openSearch(http.MethodPost, path, map[string]any{
				"doc": map[string]any{quarantine.RestoredAtField: time.Now().UTC().Format(time.RFC3339)},
			})
			if err != nil {
				return err
			}
			defer func() { _ = resp.Body.Close() }() // best-effort: nothing actionable on close failure
			if resp.StatusCode == http.StatusConflict {
				return fmt.Errorf("%w (doc %s/%s)", quarantine.ErrClaimConflict, index, id)
			}
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return fmt.Errorf("quarantine claim failed (opensearch status %d on %s/%s)", resp.StatusCode, index, id)
			}
			return nil
		},
		// Unclaim rolls the stamp back after the bus refused a produce, so the
		// envelope stays restorable. Failure is surfaced (UnclaimFailed count +
		// this log): the envelope would be replay-refused on the next run.
		Unclaim: func(ctx context.Context, index, id string) error {
			err := s.osJSON(ctx, http.MethodPost, "/"+index+"/_update/"+url.PathEscape(id),
				[]byte(`{"doc":{"`+quarantine.RestoredAtField+`":null}}`), nil)
			if err != nil {
				logError("quarantine", "flows replay-claim rollback failed — envelope will be refused on the next restore",
					map[string]any{"index": index, "doc": id, "error": err.Error()})
			}
			return err
		},
	}
	res := quarantine.Restore(r.Context(), deps, docs, tenant)
	// Replay-refused envelopes are resolved too: either their tombstone was
	// just retried or a concurrent restore owns them — they do not remain.
	remaining := int(total) - res.Restored - res.ReplayRefused
	if remaining < 0 {
		remaining = 0
	}
	if s.quarMetrics != nil {
		s.quarMetrics.RecordRestore(res.Restored, res.Failed)
	}
	s.auditQuarantineRestore(claims, sha, tenant, res)

	writeJSON(w, http.StatusOK, map[string]any{
		"matched_identity_count": matched,
		"tenant":                 tenant,
		"restored":               res.Restored,
		"failed":                 res.Failed,
		"remaining":              remaining,
		"deleted":                res.Deleted,
		"delete_failed":          res.DeleteFailed,
		"replay_refused":         res.ReplayRefused,
		"unclaim_failed":         res.UnclaimFailed,
	})
}

// auditQuarantineRestore records the act EXPLICITLY (the withAudit middleware
// also records the request coarsely) with the SecEventQuarantineRestore
// vocabulary type. Identifiers and counts only — never payload contents, and
// no token reference at all (auditUnseal's redaction rule).
func (s *server) auditQuarantineRestore(claims jwtClaims, sha, tenant string, res quarantine.RestoreResult) {
	if s.audit == nil {
		return
	}
	actorTenant, cross := principalTenant(claims)
	s.audit.Record(AuditEvent{
		Actor:    claims.Sub,
		Tenant:   actorTenant,
		Cross:    cross,
		Method:   http.MethodPost,
		Path:     quarantineReattrRoutePath,
		Status:   http.StatusOK,
		Decision: "allow",
		Detail: map[string]any{
			secobs.SecEventKey: secobs.SecEventQuarantineRestore,
			"identity_sha":     sha, // a hash of a device identity — not PII, not payload
			"tenant":           tenant,
			"restored":         res.Restored,
			"failed":           res.Failed,
			"deleted":          res.Deleted,
			"delete_failed":    res.DeleteFailed,
			"replay_refused":   res.ReplayRefused,
			"unclaim_failed":   res.UnclaimFailed,
			"actor_tenant":     actorTenant,
			"cross_tenant":     cross,
		},
	})
}
