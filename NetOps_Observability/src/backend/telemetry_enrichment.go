package backend

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/platformdb"
	"netops/backend/models"
	"netops/backend/processors"
)

// telemetry_enrichment.go — exports the device→tenant map so the ingest tier
// (Vector aggregator, correlation) can stamp a tenant_id onto every telemetry
// record at the source. This is the Phase 1 substrate of #20 (multi-tenant
// telemetry isolation); see docs/design/multitenant-telemetry-isolation.md.
//
// The Go API's discovery is the source of truth for Device.TenantID, but the
// aggregator has no inventory access — so we periodically write a small CSV
// keyed by the device-identity values that telemetry carries (the device NAME,
// which appears as syslog `hostname`, and the management ADDRESS, which appears
// as the flows `sampler_address`/`src/dst_addr`). The aggregator loads it as a
// Vector enrichment table and looks each event up by that identity.
//
// Reads do NOT depend on this file — they still use the live read-time device
// matcher (tenancy.go). The exported tag is defense-in-depth groundwork that
// Phase 2 promotes into database-enforced row policies / DLS.

const enrichmentFileName = "device_tenant.csv"

// enrichmentRow is one (identity, tenant) mapping. identity is either a device
// name or a management address; tenant is the normalized owning tenant ("" for
// global/unassigned, which is platform-only under the strict model).
type enrichmentRow struct {
	Identity string
	Tenant   string
}

// buildEnrichmentRows projects the device inventory onto the identity→tenant
// rows the ingest tier looks up. Pure (no IO) so it is unit-testable.
//
// Rules:
//   - one row per distinct non-empty device NAME and per distinct ADDRESS;
//   - tenant is the device's normalized TenantID ("" = global/platform);
//   - an identity that maps to MORE THAN ONE distinct tenant is AMBIGUOUS and is
//     omitted entirely (fail-safe: it stays untagged → "" → platform-only, never
//     leaked to a wrong tenant). NAT can collapse several devices onto one
//     address, so this guard matters.
//
// Rows are returned sorted by identity for deterministic output (stable file,
// clean diffs, reproducible tests).
func buildEnrichmentRows(devices []models.Device) []enrichmentRow {
	// identity -> set of distinct tenants seen for it.
	seen := map[string]map[string]bool{}
	add := func(identity, tenant string) {
		if identity == "" {
			return
		}
		if seen[identity] == nil {
			seen[identity] = map[string]bool{}
		}
		seen[identity][tenant] = true
	}
	for _, d := range devices {
		t := deviceTenant(d)
		add(d.Name, t)
		add(d.Address, t)
	}

	rows := make([]enrichmentRow, 0, len(seen))
	for identity, tenants := range seen {
		if len(tenants) != 1 {
			continue // ambiguous identity — omit (fail-safe).
		}
		for t := range tenants {
			rows = append(rows, enrichmentRow{Identity: identity, Tenant: t})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Identity < rows[j].Identity })
	return rows
}

// writeEnrichmentCSV atomically writes the rows as a headered CSV to
// dir/device_tenant.csv (temp file + rename, so a reader never sees a partial
// file). Header is `identity,tenant_id` — matched by the Vector enrichment
// table and the correlation loader.
func writeEnrichmentCSV(dir string, rows []enrichmentRow) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".device_tenant-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename.

	w := csv.NewWriter(tmp)
	if err := w.Write([]string{"identity", "tenant_id"}); err != nil {
		tmp.Close()
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{r.Identity, r.Tenant}); err != nil {
			tmp.Close()
			return err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// os.CreateTemp creates 0600, but this file IS the shared cross-service plane:
	// the Vector aggregator and the correlation engine (different uids) must read
	// it. 0600 left them with PermissionError → silently empty tenant maps.
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, enrichmentFileName))
}

// startTenantEnrichment runs the export loop until ctx is cancelled. It is a
// no-op unless TENANT_ENRICHMENT_DIR is set (so the file backend / dev builds
// without the shared volume are unaffected). It writes once immediately, then
// on every TENANT_ENRICHMENT_INTERVAL tick (default 60s).
func (s *server) startTenantEnrichment(ctx context.Context) {
	dir := os.Getenv("TENANT_ENRICHMENT_DIR")
	if dir == "" {
		return
	}
	interval := 60 * time.Second
	if v := os.Getenv("TENANT_ENRICHMENT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	write := func() {
		rows := buildEnrichmentRows(s.discovery.Devices())
		if err := writeEnrichmentCSV(dir, rows); err != nil {
			log.Printf("tenant-enrichment: write %s: %v", dir, err)
			return
		}
		log.Printf("tenant-enrichment: wrote %d identity rows to %s/%s", len(rows), dir, enrichmentFileName)
	}
	go func() {
		write()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
}

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

// regenProcessorsAsync rebuilds the config after a rule mutation without
// holding the request; the periodic writer is the safety net (§10: failures
// are logged, and the next tick retries).
func (s *server) regenProcessorsAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.writeProcessorsConfig(ctx); err != nil {
			log.Printf("processors: regen after mutation: %v", err)
		}
	}()
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
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				wctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if err := s.writeProcessorsConfig(wctx); err != nil {
					log.Printf("processors: periodic write: %v", err)
				}
				cancel()
			}
		}
	}()
}

// decodeProcessorRule reads and validates an operator payload; `enabled`
// defaults to TRUE when omitted (a rule that silently did nothing would be
// the worst failure mode — same contract as maintenance windows).
func decodeProcessorRule(w http.ResponseWriter, r *http.Request) (processors.Rule, bool) {
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return processors.Rule{}, false
	}
	var in processors.Rule
	if err := json.Unmarshal(raw, &in); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return processors.Rule{}, false
	}
	var probe struct {
		Enabled *bool `json:"enabled"`
	}
	if json.Unmarshal(raw, &probe) == nil && probe.Enabled == nil {
		in.Enabled = true
	}
	if err := in.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return processors.Rule{}, false
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

// processorPreviewRequest is the dry-run body: a sample event + the lane.
type processorPreviewRequest struct {
	Lane  string         `json:"lane"`
	Event map[string]any `json:"event"`
}

func (s *server) handleProcessorByID(w http.ResponseWriter, r *http.Request) {
	if s.processors == nil {
		writeError(w, http.StatusNotImplemented, errors.New("processor store unavailable"))
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/pipeline/processors/")

	// POST /api/pipeline/processors/preview — simulate the caller's OWN rules
	// against a sample event (the incident-policy simulator pattern). The
	// event is data: it is echoed back shaped, never stored or executed.
	if rest == "preview" {
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
			writeError(w, http.StatusBadRequest, errors.New("lane must be one of applogs, syslog, snmptrap, cloudlogs, flows"))
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
		// The simulation runs under the CALLER's tenant: stamp the sample the
		// way the router's enrichment would, so the tenant guard behaves.
		if !cross {
			req.Event["tenant_id"] = tenant
		}
		simTenant := tenant
		if cross {
			simTenant = strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", req.Event["tenant_id"])))
		}
		shaped, applied := processors.Simulate(rules, req.Lane, simTenant, req.Event)
		if applied == nil {
			applied = []processors.Applied{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"event": shaped, "applied": applied})
		return
	}

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
