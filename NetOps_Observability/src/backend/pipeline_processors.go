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

	"netops/backend/internal/platformdb"
	"netops/backend/processors"
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
	content := processors.GenerateRouterConfig(rules)
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
