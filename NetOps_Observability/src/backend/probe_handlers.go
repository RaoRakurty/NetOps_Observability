package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/dem"
	"netops/backend/internal/dem/experience"
	"netops/backend/internal/platformdb"
)

// probe_handlers.go — read API for active-measurement results. STAMP metrics go
// to VictoriaMetrics (queried via /api/metrics); the traceroute path topology is
// served here for the Network Path UI.

// handleProbePaths returns the latest traceroute path per (VANTAGE, destination,
// method). Every path carries the vantage that measured it: two probers observing
// the same destination from different places are two DISTINCT paths (contract §2.2)
// and both are returned — they used to overwrite each other in one shared key.
// When the prober runs as a sidecar it shares topology via PROBE_PATHS_FILE (a
// shared volume) — serve that file if present; otherwise serve the in-process store
// (collector running inside the API). Authenticated (the /api mux is withAuth).
func (s *server) handleProbePaths(w http.ResponseWriter, r *http.Request) {
	// POST = a REMOTE vantage publishing its own traces (probe_paths_ingest.go): the
	// only transport a prober inside a customer LAN has, since it cannot reach the
	// platform's key-value store and we will not expose one to an untrusted segment.
	if r.Method == http.MethodPost {
		s.handleProbePathsPush(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Primary: the key-value store (sidecar probers publish here — ADR 0001), merged
	// across every vantage that has published.
	if collectors.RedisAddr() != "" {
		if paths, err := collectors.FetchProbePathsAll(r.Context()); err == nil && len(paths) > 0 {
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(paths) // best-effort: a failed encode/write means the client is gone
			return
		}
	}
	// Fallback: shared file, then the in-process store.
	if path := os.Getenv("PROBE_PATHS_FILE"); path != "" {
		// #nosec G304 -- path is the operator-configured PROBE_PATHS_FILE, not user input
		if data, err := os.ReadFile(path); err == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data) // best-effort: status committed; a failed write means the client is gone
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(s.mergedProbePaths(collectors.Paths.All())) // best-effort: a failed encode/write means the client is gone
}

// mergedProbePaths folds the remote vantages' pushed traces into whatever the local
// transport produced. Same-vantage duplicates keep the newest measurement.
func (s *server) mergedProbePaths(local []collectors.PathResult) []collectors.PathResult {
	if s.remotePaths == nil {
		return local
	}
	out := append([]collectors.PathResult{}, local...)
	return append(out, s.remotePaths.All(time.Now().UTC())...)
}

// ── Digital Experience Monitoring (S17, 2026-09-05) ──────────────────────────
//
// The DEM wiring lives in THIS file rather than a new one: the root package is
// at its file-count ratchet (package_growth_guard_test.go), and the domain logic
// is where CLAUDE.md §2 wants it — internal/dem. What is left here is only the
// integration seam: backend selection, the RBAC gate mapping, and the
// construction of the module's HTTP surface and its work-queue projector.
//
// See docs/design/DEM_PLUMBING_2026-09-05.md and docs/design/DEM_DATA_MODEL_2026-09-05.md
// (the product design of record is docs/design/DEM_2026-09-05.md).

// newDEMStore picks the catalogue backend, exactly as the BGP alert policy and
// the security control plane do: Postgres (migration 0043, FORCE-RLS) when it is
// active, the file store otherwise.
//
// A corrupt file still SERVES (an empty catalogue) but says so — a catalogue
// that failed to load must never look like one a tenant never wrote, because the
// visible consequence of both is the same empty table.
func newDEMStore() dem.Catalogue {
	if ps, ok := platformdb.ActivePG(); ok {
		return dem.NewPGStore(ps.DB())
	}
	fs := dem.NewFileStore(envOr(dem.EnvTargetsFile, "/data/dem_targets.json"))
	if err := fs.LoadErr(); err != nil {
		logError("dem", "the experience target catalogue could not be read — it starts EMPTY and NO target will be measured until it is re-added or the file is repaired",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// demAuthz maps the module's gates onto the RBAC model.
//
// GATE CHOICE (§3a rule 3): experience targets are per-tenant OPERATOR data
// about the tenant's own services — not platform plumbing — so both gates are
// requirePerm(infrastructure, …) plus a tenant filter, the same gate the probe
// path surfaces already use. A platform gate here would be wrong in BOTH
// directions: it would lock tenant admins out of their own targets and let a
// cross-tenant principal manage everyone's.
func (s *server) demAuthz(w http.ResponseWriter, r *http.Request, gate dem.Gate) (dem.Principal, bool) {
	var level int
	switch gate {
	case dem.GateRead:
		level = LevelRead
	case dem.GateWrite:
		level = LevelWrite
	default:
		// The module declares exactly two gates. An unknown gate is a wiring
		// bug, and the safe answer to a gate we cannot map is refusal.
		writeError(w, http.StatusForbidden, errors.New("unsupported gate"))
		return dem.Principal{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return dem.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	if tenant == TenantGlobal {
		// The platform tenant is not a customer: treat it as scopeless so the
		// module's own refusal fires rather than reading a shared bucket.
		tenant = ""
	}
	return dem.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// demQuerier adapts the platform's VictoriaMetrics instant-query client to the
// module's Querier seam. The tenant scoping arrives as extra_filters[] built by
// dem.TenantFilter — the backend AND's them into every metric in the expression,
// which is why a crafted expression cannot evade them.
type demQuerier struct{ s *server }

func (q demQuerier) Instant(ctx context.Context, expr string, filters []string) ([]dem.Sample, error) {
	rows, err := q.s.vmInstantScoped(ctx, expr, filters)
	if err != nil {
		return nil, err
	}
	out := make([]dem.Sample, 0, len(rows))
	for _, r := range rows {
		out = append(out, dem.Sample{Labels: r.Labels, Value: r.Value})
	}
	return out, nil
}

// buildDEMAPI builds the module's HTTP surface. It is built unconditionally: the
// catalogue is manageable with the feature off (an operator must be able to
// prepare targets before enabling collection), and every score then says the
// feature is off instead of showing an empty table that reads as "all well".
func (s *server) buildDEMAPI(cat dem.Catalogue) (*dem.API, error) {
	var q dem.Querier
	if metricsUpstreamIsVictoria(s.metricsBase()) {
		q = demQuerier{s: s}
	}
	return dem.NewAPI(dem.APIDeps{
		Authz:      s.demAuthz,
		Targets:    cat,
		Metrics:    q,
		Enabled:    envBool(dem.EnvFeatureFlag),
		Now:        func() time.Time { return time.Now().UTC() },
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(m string, f map[string]any) { logWarn("dem", m, f) },
		Counters:   s.demMetrics,
	})
}

// demPublisher is the projector's transport: the same key-value channel the WAN
// circuit projector already uses to hand the prober its work.
type demPublisher struct{}

func (demPublisher) Publish(ctx context.Context, targets []dem.WireTarget, ttlSec int) error {
	return collectors.PublishDEMTargets(ctx, targets, ttlSec)
}

// The three DEM route entry points. They resolve s.demAPI at REQUEST time (a
// bound method value would capture a nil surface at registration time), and the
// module's handlers nil-check their receiver, so an unbuilt surface answers 404
// rather than degrading into an unscoped read.
func (s *server) handleDEMTargets(w http.ResponseWriter, r *http.Request) {
	s.demAPI.HandleTargets(w, r)
}

func (s *server) handleDEMTargetItem(w http.ResponseWriter, r *http.Request) {
	s.demAPI.HandleTargetItem(w, r)
}

func (s *server) handleDEMExperience(w http.ResponseWriter, r *http.Request) {
	s.demAPI.HandleExperience(w, r)
}

// DEM-EXPERIENCE-BEGIN — the Digital Experience causality surface
// (internal/dem/experience): journeys, changes, evidence, hypotheses, derived
// experience incidents, the published score and per-source data health.
//
// It sits ABOVE internal/dem: that package answers "was this check healthy",
// this one answers "was the experience good, and which seam owns the fix". The
// wiring lives HERE beside the rest of the DEM integration rather than in a new
// root file — the root package is at its file-count ratchet, and the domain
// logic is where CLAUDE.md §2 wants it.
//
// See docs/design/dem-architecture.md and docs/design/DEM_2026-09-05.md §M.

// newExperienceStore picks the backend for the two PERSISTED objects (journey
// definitions and the normalized change feed): Postgres (migration 0044,
// FORCE-RLS) when it is active, the file store otherwise.
//
// A corrupt file still SERVES (an empty store) but says so — a store that
// failed to load must never look like one a tenant never wrote, because the
// visible consequence of both is the same empty table.
func newExperienceStore() experience.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return experience.NewPGStore(ps.DB())
	}
	fs := experience.NewFileStore(envOr(experience.EnvStoreFile, "/data/dem_experience.json"))
	if err := fs.LoadErr(); err != nil {
		logError("dem", "the experience journey/change store could not be read — it starts EMPTY and no journey will be reported until it is re-added or the file is repaired",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// experienceScorePolicy loads the versioned score policy: the embedded product
// policy, optionally replaced by an operator file. A BAD override is loud and
// the embedded policy stands — a scoring policy that silently half-applied
// would be worse than one that was ignored.
func experienceScorePolicy() experience.ScorePolicy {
	policy, err := experience.EmbeddedScorePolicy()
	if err != nil {
		// Unreachable in a built binary (the package test proves the embedded
		// file parses), but a nil-weight policy would publish no score at all,
		// so it is reported rather than swallowed.
		logError("dem", "the embedded experience score policy could not be parsed — no experience score will be published",
			map[string]any{"err": err.Error()})
		return experience.ScorePolicy{}
	}
	path := os.Getenv(experience.EnvScorePolicyFile)
	if path == "" {
		return policy
	}
	raw, rerr := os.ReadFile(path) // #nosec G304 — an operator-supplied policy path, read-only, and the parser refuses anything outside its closed grammar
	if rerr != nil {
		logError("dem", "the experience score policy override could not be read — the shipped policy is in force instead",
			map[string]any{"err": rerr.Error(), "path": path})
		return policy
	}
	override, perr := experience.ParseScorePolicy(string(raw))
	if perr != nil {
		logError("dem", "the experience score policy override is invalid — the shipped policy is in force instead",
			map[string]any{"err": perr.Error(), "path": path})
		return policy
	}
	override.Source = path
	logInfo("dem", "an operator experience score policy is in force", map[string]any{
		"path": path, "policy": override.Name, "version": override.Version})
	return override
}

// buildExperienceAPI builds the causality surface. Like the catalogue surface it
// is built UNCONDITIONALLY: with collection off, every view says so rather than
// rendering an empty table that reads as "all well".
func (s *server) buildExperienceAPI(store experience.Store, cat dem.Catalogue) (*experience.API, error) {
	var q dem.Querier
	if metricsUpstreamIsVictoria(s.metricsBase()) {
		q = demQuerier{s: s}
	}
	return experience.NewAPI(experience.Deps{
		Authz:   s.demAuthz,
		Store:   store,
		Targets: cat,
		Metrics: q,
		Policy:  experienceScorePolicy(),
		Enabled: envBool(dem.EnvFeatureFlag),
		// The AI investigator needs BOTH the platform copilot and its own
		// switch: a feature that can send evidence to a model gets its own.
		InvestigatorEnabled: envBool("FEATURE_COPILOT") && envBool(experience.EnvInvestigatorFlag),
		Now:                 func() time.Time { return time.Now().UTC() },
		WriteJSON:           writeJSON,
		WriteError:          writeError,
		LogWarn:             func(m string, f map[string]any) { logWarn("dem", m, f) },
		Counters:            s.demExperienceMetrics,
	})
}

// The experience route entry points. They resolve s.experienceAPI at REQUEST
// time (a bound method value would capture a nil surface at registration time),
// and the module's handlers nil-check their receiver, so an unbuilt surface
// answers 404 rather than degrading into an unscoped read.
func (s *server) handleDEMOverview(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleOverview(w, r)
}

func (s *server) handleDEMIncidents(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleIncidents(w, r)
}

func (s *server) handleDEMIncidentItem(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleIncidentItem(w, r)
}

func (s *server) handleDEMJourneys(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleJourneys(w, r)
}

func (s *server) handleDEMJourneyItem(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleJourneyItem(w, r)
}

func (s *server) handleDEMCoverage(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleCoverage(w, r)
}

func (s *server) handleDEMChanges(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleChanges(w, r)
}

func (s *server) handleDEMDataHealth(w http.ResponseWriter, r *http.Request) {
	s.experienceAPI.HandleDataHealth(w, r)
}

// DEM-EXPERIENCE-END
