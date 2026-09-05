package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
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

// demFlowQuerier adapts netops.flows to the experience surface's passive-flow
// lane (tracker 252) — the SECOND anchor-capable evidence class.
//
// Isolation (§3a) is enforced THREE times over, because the flows row policy
// shares UNTAGGED rows into every tenant scope (the hybrid model) and one
// forgotten filter would be a cross-tenant leak:
//
//  1. the ClickHouse `tenant_scope` setting, derived from the CALLER's claims by
//     the one canonical rule (chTenantScopeFor) — never from the tenant string
//     the caller passed, and refused outright when the two disagree;
//  2. addrTenantClauseFor, the same app-layer narrowing every other flows read
//     uses, which bounds a scoped principal to flows touching ITS OWN devices'
//     addresses and returns NOTHING when it has none (default-closed);
//  3. the endpoint list itself, which comes from the tenant's own DEM catalogue.
//
// It reads only aggregate counters — never a raw flow row — so nothing that
// could identify a conversation leaves ClickHouse.
type demFlowQuerier struct{ s *server }

// demFlowMaxRows bounds the grouped result. The grouping key is (server
// endpoint, exporter), so this is far above anything a real catalogue produces
// and exists to make the query provably finite rather than to trim an answer.
const demFlowMaxRows = 2000

func (q demFlowQuerier) FlowStats(ctx context.Context, tenant string, subjects []experience.FlowSubject,
	start, end time.Time) ([]experience.FlowStats, error) {

	if len(subjects) == 0 {
		return nil, nil
	}
	claims, ok := userFrom(ctx)
	if !ok {
		// A read with no principal cannot be scoped, so it does not happen.
		return nil, errors.New("dem flow: the request carries no principal, so the wire cannot be read for anyone")
	}
	scope := chTenantScopeFor(claims)
	if scope != strings.ToLower(strings.TrimSpace(tenant)) {
		// The experience surface resolves ONE concrete tenant before it calls
		// here; a mismatch means a wiring mistake, and the safe answer to a
		// wiring mistake about tenancy is no data at all.
		return nil, fmt.Errorf("dem flow: the caller's tenant scope does not match the requested tenant, so the read is refused")
	}
	clause, empty := q.s.addrTenantClauseFor(claims, "src_addr", "dst_addr")
	if empty {
		// Default-closed: this principal can see no device addresses, so it can
		// see no flows. Reported as an empty answer, not as an error — the
		// surface renders "no flow record touched any declared subject".
		return nil, nil
	}

	addrs := make([]string, 0, len(subjects)*2)
	seen := map[string]bool{}
	for _, sub := range subjects {
		for _, ep := range sub.Endpoints {
			if ep.Addr == "" || seen[ep.Addr] {
				continue
			}
			seen[ep.Addr] = true
			addrs = append(addrs, ep.Addr)
		}
	}
	if len(addrs) == 0 {
		return nil, nil
	}
	sort.Strings(addrs)
	in := sqlInList(addrs)

	// The server-side endpoint of each flow: the declared address is whichever
	// end of the conversation we recognise, and its port is that end's port. A
	// flow between two declared endpoints is attributed to its destination.
	epExpr := "multiIf(dst_addr IN (" + in + "), concat(dst_addr, ':', toString(dst_port)), concat(src_addr, ':', toString(src_port)))"
	sql := "SELECT " + epExpr + " AS ep, sampler_address AS exporter, " +
		"count() AS flows, " +
		"countIf(proto = 6) AS tcp_flows, " +
		"countIf(proto = 6 AND tcp_flags != 0) AS flag_flows, " +
		"countIf(proto = 6 AND bitAnd(tcp_flags, 4) != 0) AS reset_flows, " +
		"toInt64(sum(bytes * if(sampling_rate = 0, 1, sampling_rate))) AS bytes, " +
		"toInt64(sum(packets * if(sampling_rate = 0, 1, sampling_rate))) AS packets, " +
		"toUnixTimestamp(min(ts)) AS first_seen, toUnixTimestamp(max(ts)) AS last_seen " +
		"FROM netops.flows WHERE ts >= toDateTime(" + strconv.FormatInt(start.Unix(), 10) + ") " +
		"AND ts < toDateTime(" + strconv.FormatInt(end.Unix(), 10) + ") " +
		"AND (src_addr IN (" + in + ") OR dst_addr IN (" + in + "))" + clause + " " +
		"GROUP BY ep, exporter ORDER BY flows DESC LIMIT " + strconv.Itoa(demFlowMaxRows) + " FORMAT JSON"

	rows, err := q.s.chRowsScope(ctx, scope, sql, "api:dem-flow")
	if err != nil {
		return nil, err
	}
	return foldDEMFlowRows(subjects, rows), nil
}

// foldDEMFlowRows attributes each (endpoint, exporter) aggregate to the DEM
// subjects that declared that endpoint. Kept as a free function over plain
// values so the attribution is unit-tested without ClickHouse.
//
// A row may land on more than one subject when two subjects declare the same
// address; that is the operator's declaration, and splitting the counters
// between them would invent a division nothing measured.
func foldDEMFlowRows(subjects []experience.FlowSubject, rows []map[string]any) []experience.FlowStats {
	type agg struct {
		st        experience.FlowStats
		exporters map[string]bool
	}
	acc := map[string]*agg{}
	order := make([]string, 0, len(subjects))

	for _, row := range rows {
		ep, _ := row["ep"].(string)
		addr, portStr, found := strings.Cut(ep, ":")
		if !found {
			continue
		}
		port, perr := strconv.Atoi(portStr)
		if perr != nil {
			continue
		}
		for _, sub := range subjects {
			if !flowSubjectOwns(sub, addr, port) {
				continue
			}
			a, ok := acc[sub.Subject]
			if !ok {
				a = &agg{st: experience.FlowStats{Subject: sub.Subject}, exporters: map[string]bool{}}
				acc[sub.Subject] = a
				order = append(order, sub.Subject)
			}
			a.st.Flows += chRowInt(row["flows"])
			a.st.TCPFlows += chRowInt(row["tcp_flows"])
			a.st.FlagBearingFlows += chRowInt(row["flag_flows"])
			a.st.ResetFlows += chRowInt(row["reset_flows"])
			a.st.Bytes += chRowInt(row["bytes"])
			a.st.Packets += chRowInt(row["packets"])
			if x, _ := row["exporter"].(string); x != "" {
				a.exporters[x] = true
			}
			if ts := chRowInt(row["first_seen"]); ts > 0 {
				t := time.Unix(ts, 0).UTC()
				if a.st.FirstSeen.IsZero() || t.Before(a.st.FirstSeen) {
					a.st.FirstSeen = t
				}
			}
			if ts := chRowInt(row["last_seen"]); ts > 0 {
				t := time.Unix(ts, 0).UTC()
				if t.After(a.st.LastSeen) {
					a.st.LastSeen = t
				}
			}
		}
	}

	sort.Strings(order)
	out := make([]experience.FlowStats, 0, len(order))
	for _, id := range order {
		a := acc[id]
		exporters := make([]string, 0, len(a.exporters))
		for e := range a.exporters {
			exporters = append(exporters, e)
		}
		sort.Strings(exporters)
		a.st.Exporters = exporters
		out = append(out, a.st)
	}
	return out
}

// flowSubjectOwns reports whether a subject declared this server endpoint. A
// declared port of 0 means "any port on that address", which is the honest
// reading of an ICMP target: it names a host, not a service.
func flowSubjectOwns(sub experience.FlowSubject, addr string, port int) bool {
	for _, ep := range sub.Endpoints {
		if ep.Addr != addr {
			continue
		}
		if ep.Port == 0 || ep.Port == port {
			return true
		}
	}
	return false
}

// chRowInt reads a ClickHouse JSON numeric, which arrives as a float64 for a
// plain number and as a string for the 64-bit types. A value it cannot read is
// 0 — the counters it feeds are all sums, and a malformed one must not be
// guessed at.
func chRowInt(v any) int64 {
	switch t := v.(type) {
	case float64:
		return int64(t)
	case int64:
		return t
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
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
		// The passive-flow lane (tracker 252): the second anchor-capable
		// evidence class, and the one that lets a live tenant reach a CONFIRMED
		// verdict instead of stopping at suspected. Wired unconditionally —
		// with ClickHouse unreachable the source reports misconfigured with its
		// reason, which is what an operator needs to see.
		Flows:   demFlowQuerier{s: s},
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
