package backend

// bgp_alerts.go — the THIN root adapter for internal/bgpwatch (BGP ops tracker
// rows #1 bogons, #5 leak/hijack classes, #10 alerting). §2: no domain logic
// lives here. Everything below is a production seam — the outbound measurement,
// the tenant list, the watchlist read, the BMP peer/update reads, the notifier,
// the bus transport, the RBAC gate — handed to a package that holds no ambient
// authority of its own.
//
// REMOVAL RECIPE (the removable-module discipline the security lane set):
//
//	rm internal/bgpwatch bgp_alerts.go bgp_alerts_isolation_test.go
//	rm internal/platformdb/migrations/0041_bgp_alert_policy.sql (+ its rollback)
//	delete every main.go line between a `BGP-WATCH-BEGIN` marker and its
//	matching `BGP-WATCH-END` (the import, the two server fields, the
//	construction, the worker start, the three routes and the metrics write)
//	drop the four /api/bgp/alerts* + /api/bgp/bogons rows from the route ledger
//
// …and `go build ./...` is green again. Nothing in the core imports bgpwatch.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/bgpdepth"
	"netops/backend/internal/bgpwatch"
	"netops/backend/internal/bmp"
	"netops/backend/internal/platformdb"
	"netops/backend/models"
)

// bgpWatchSightingLimit bounds how many recent live-feed / BMP records one
// evaluation pass screens for bogons (§9).
const bgpWatchSightingLimit = 200

// buildBGPWatch assembles the evaluator. It returns (nil, nil) when the feature
// flag is off — the HTTP surface is still built (the embedded bogon set is
// useful with no evaluator), and it answers an honest "not enabled".
func (s *server) buildBGPWatch(policies bgpwatch.PolicyStore, bogons *bgpwatch.BogonSet) (*bgpwatch.Evaluator, error) {
	if !envBool(bgpwatch.EnvFeatureFlag) {
		return nil, nil
	}
	return bgpwatch.New(bgpwatch.Deps{
		Now:       func() time.Time { return time.Now().UTC() },
		Interval:  durationOr(bgpwatch.EnvInterval, bgpwatch.DefaultInterval),
		Cooldown:  durationOr(bgpwatch.EnvCooldown, bgpwatch.DefaultCooldown),
		Tenants:   s.bgpWatchTenants,
		Watchlist: s.bgpWatchPrefixes,
		Policies:  policies,
		Observe:   s.bgpWatchObserve,
		Peers:     s.bgpWatchPeers,
		Sightings: s.bgpWatchSightings,

		// Notifications ride the SAME dispatcher every other evaluator uses, so
		// a BGP alert reaches whatever channels the tenant already configured
		// (the cloud-monitor evaluator's exact shape).
		Notify:  func(a bgpwatch.Alert) { s.notifier.Dispatch(bgpWatchAlertToModel(a)) },
		Resolve: func(a bgpwatch.Alert) { s.notifier.DispatchResolve(bgpWatchAlertToModel(a)) },

		// Transport: the same Vector bus-bridge produce path every other Go
		// producer uses (no Kafka client in the backend, §6 allowlist).
		Publish: bgpwatch.PublisherFunc(func(ctx context.Context, topic string, recs []bgpwatch.Record) (int, error) {
			out := make([]proxyRecord, 0, len(recs))
			for _, r := range recs {
				out = append(out, proxyRecord{Key: r.Key, Value: r.Value})
			}
			return produceJSON(ctx, topic, out)
		}),
		EvidenceTopic: os.Getenv(bgpwatch.EnvEvidenceTopic),

		Bogons:           bogons,
		BogonFeedEnabled: envBool(bgpwatch.EnvBogonFeed),
		BogonFeedURL:     os.Getenv(bgpwatch.EnvBogonFeedURL),
		BogonFetcher:     s.bgpFetch,

		LogWarn:  func(m string, f map[string]any) { logWarn("bgp-watch", m, f) },
		LogError: func(m string, f map[string]any) { logError("bgp-watch", m, f) },
	})
}

// newBGPAlertPolicyStore picks the backend, exactly as the security control
// plane does: Postgres (migration 0041, FORCE-RLS) when it is active, the file
// store otherwise. A corrupt file still SERVES (empty policy) but says so —
// a policy that failed to load must never look like one a tenant never set.
func newBGPAlertPolicyStore() bgpwatch.PolicyStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return bgpwatch.NewPGStore(ps.DB())
	}
	fs := bgpwatch.NewFileStore(envOr(bgpwatch.EnvConfigFile, "/data/bgp_alert_policy.json"))
	if err := fs.LoadErr(); err != nil {
		logError("bgp-watch", "BGP alert policy could not be read — the evaluator will use a LEARNED origin baseline and run NO route-leak heuristic for every tenant",
			map[string]any{"err": err.Error()})
	}
	return fs
}

// buildBGPWatchAPI builds the HTTP surface. It is built unconditionally: the
// embedded bogon set is a real answer with or without the evaluator.
func (s *server) buildBGPWatchAPI(policies bgpwatch.PolicyStore, bogons *bgpwatch.BogonSet, eval *bgpwatch.Evaluator) (*bgpwatch.API, error) {
	return bgpwatch.NewAPI(bgpwatch.APIDeps{
		Authz:            s.bgpWatchAuthz,
		Policies:         policies,
		Bogons:           bogons,
		BogonFeedEnabled: envBool(bgpwatch.EnvBogonFeed),
		Eval:             eval,
		Now:              func() time.Time { return time.Now().UTC() },
		WriteJSON:        writeJSON,
		WriteError:       writeError,
		LogWarn:          func(m string, f map[string]any) { logWarn("bgp-watch", m, f) },
	})
}

// bgpWatchAuthz maps the module's gates onto the RBAC model.
//
// GATE CHOICE (§3a rule 3): BGP alerts and the alert policy are per-tenant
// OPERATOR data about the tenant's own address space, not platform plumbing —
// so both gates are requirePerm(infrastructure, …) plus a tenant filter, the
// same gate /api/bgp/watchlist and /api/bgp/feed already use. A platform gate
// here would be wrong in BOTH directions: it would lock tenant admins out of
// their own alerts and let a cross-tenant principal read everyone's.
func (s *server) bgpWatchAuthz(w http.ResponseWriter, r *http.Request, gate bgpwatch.Gate) (bgpwatch.Principal, bool) {
	var level int
	switch gate {
	case bgpwatch.GateRead:
		level = LevelRead
	case bgpwatch.GateWrite:
		level = LevelWrite
	default:
		// The module declares exactly two gates. An unknown gate is a wiring
		// bug, and the safe answer to a gate we cannot map is refusal.
		writeError(w, http.StatusForbidden, errors.New("unsupported gate"))
		return bgpwatch.Principal{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", level)
	if !ok {
		return bgpwatch.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	if tenant == TenantGlobal {
		// The platform tenant is not a customer: treat it as scopeless so the
		// module's own refusal fires rather than reading a shared bucket.
		tenant = ""
	}
	return bgpwatch.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// bgpWatchAlertToModel is the one-line adapter from the module's Alert to the
// platform's. Keeping bgpwatch free of models.Alert is what lets it stay a leaf.
func bgpWatchAlertToModel(a bgpwatch.Alert) models.Alert {
	out := models.Alert{
		ID: a.ID, Rule: a.Rule, Severity: a.Severity,
		Summary: a.Summary, Description: a.Detail,
		Labels: map[string]string{}, FiredAt: a.FiredAt,
	}
	for k, v := range a.Labels {
		out.Labels[k] = v
	}
	// The tenant rides in the labels (never in the summary), so a channel that
	// routes by label can, and a channel that does not simply ignores it.
	out.Labels["tenant"] = a.Tenant
	if a.ResolvedAt != nil {
		out.ResolvedAt = a.ResolvedAt
	}
	return out
}

// bgpWatchTenants lists the tenants the evaluator walks. The platform/global
// tenant is deliberately excluded: an alert with no owning customer has nobody
// to attribute it to, and stamping one would be inventing provenance (§10).
func (s *server) bgpWatchTenants() []string {
	if s.tenants == nil {
		return nil
	}
	out := make([]string, 0, 8)
	for _, t := range s.tenants.List() {
		id := normTenant(t.ID)
		if id == "" || id == TenantGlobal || t.Status == TenantStatusSuspended {
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// bgpWatchPrefixes reads ONE tenant's watched prefixes through the same
// FORCE-RLS store the watchlist API uses (§3a rule 4). cross is ALWAYS false:
// a worker pass is scoped to one tenant.
func (s *server) bgpWatchPrefixes(ctx context.Context, tenant string) ([]string, error) {
	if s.bgpWatch == nil {
		return nil, errors.New("BGP watchlist requires the relational store")
	}
	list, err := s.bgpWatch.List(ctx, tenant, false)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if e.Kind != "prefix" {
			continue
		}
		if p, kind := bgpNormalizeResource(e.Resource); kind == "prefix" {
			out = append(out, p)
		}
	}
	return out, nil
}

// bgpWatchObserve MEASURES one prefix through the existing cached RIPEstat
// client. Each half fails independently and an unmeasurable half leaves its
// field zero — the classifier then reports what it could and could not see,
// rather than treating an absent measurement as a clean one.
func (s *server) bgpWatchObserve(ctx context.Context, prefix string) (bgpwatch.Observation, error) {
	if s.bgpFetch == nil {
		return bgpwatch.Observation{}, errors.New("BGP fetcher not initialised")
	}
	obs := bgpwatch.Observation{Prefix: prefix, FetchedAt: time.Now().UTC()}

	data, err := s.bgpFetch.ripestat(ctx, "routing-status", prefix, "", bgpCacheTTLStatus)
	if err != nil {
		// The routing status IS the measurement. Without it there is nothing to
		// classify, so the whole observation is honestly "not measured".
		return obs, err
	}
	var rs struct {
		Announced  *bool `json:"announced"`
		Visibility struct {
			V4 struct {
				TotalRISPeers int `json:"total_ris_peers"`
				RISPeersSeen  int `json:"ris_peers_seeing"`
			} `json:"v4"`
			V6 struct {
				TotalRISPeers int `json:"total_ris_peers"`
				RISPeersSeen  int `json:"ris_peers_seeing"`
			} `json:"v6"`
		} `json:"visibility"`
	}
	if err := json.Unmarshal(data, &rs); err != nil {
		return obs, err
	}
	obs.Measured = true
	if rs.Announced != nil {
		obs.Announced, obs.AnnouncedKnown = *rs.Announced, true
	}
	obs.PeersSeeing = rs.Visibility.V4.RISPeersSeen + rs.Visibility.V6.RISPeersSeen
	obs.PeersTotal = rs.Visibility.V4.TotalRISPeers + rs.Visibility.V6.TotalRISPeers

	// Paths, with the same source + fallback the AS-path graph uses.
	obs.Paths = s.bgpWatchPaths(ctx, prefix)

	// RPKI, judged against the origin REALLY in the table (never a parameter).
	res := bgpdepth.ValidateRPKI(ctx, s.bgpFetch, time.Now, s.bgpFetch.bgpOrigin, prefix, "")
	if res.Error == "" {
		obs.RPKIState, obs.RPKIOrigin, obs.RPKIReason = string(res.State), res.Origin, res.Reason
	}
	return obs, nil
}

// bgpWatchPaths reads the per-collector AS paths. bgp-state carries the peer
// identity we need to COUNT vantage points; looking-glass is the fallback.
func (s *server) bgpWatchPaths(ctx context.Context, prefix string) []bgpwatch.VantagePath {
	out := []bgpwatch.VantagePath{}
	data, err := s.bgpFetch.RIPEstat(ctx, "bgp-state", prefix, "", bgpdepth.ASPathCacheTTL)
	if err == nil {
		var body struct {
			BGPState []struct {
				SourceID string            `json:"source_id"`
				Path     []json.RawMessage `json:"path"`
			} `json:"bgp_state"`
		}
		if json.Unmarshal(data, &body) == nil {
			for _, e := range body.BGPState {
				if len(out) >= bgpdepth.RPKIMaxPrefixes*20 { // bounded (§9)
					break
				}
				hops := make([]uint32, 0, len(e.Path))
				for _, n := range e.Path {
					if v, ok := bgpdepth.ParseASNValue(n); ok {
						hops = append(hops, v)
					}
				}
				if hops = bgpdepth.CompressPath(hops); len(hops) > 0 {
					out = append(out, bgpwatch.VantagePath{Peer: e.SourceID, Path: hops})
				}
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	// Fallback: looking-glass. It groups peers under an RRC, so the vantage
	// identity is the RRC + the peer's ASN — still a countable, distinct source.
	lg, err := s.bgpFetch.RIPEstat(ctx, "looking-glass", prefix, "", bgpdepth.ASPathCacheTTL)
	if err != nil {
		return out
	}
	var body struct {
		RRCs []struct {
			RRC   string `json:"rrc"`
			Peers []struct {
				ASPath string `json:"as_path"`
				Peer   string `json:"peer"`
			} `json:"peers"`
		} `json:"rrcs"`
	}
	if json.Unmarshal(lg, &body) != nil {
		return out
	}
	for _, rrc := range body.RRCs {
		for _, p := range rrc.Peers {
			if len(out) >= 1000 {
				return out
			}
			hops := bgpWatchParsePathString(p.ASPath)
			if len(hops) == 0 {
				continue
			}
			out = append(out, bgpwatch.VantagePath{Peer: rrc.RRC + "/" + p.Peer, Path: hops})
		}
	}
	return out
}

// bgpWatchParsePathString parses "3356 64500 64496" conservatively: a token we
// cannot read DROPS THE WHOLE PATH rather than splicing across the gap, which
// would invent an adjacency (the bgpdepth graph builder's rule).
func bgpWatchParsePathString(s string) []uint32 {
	var out []uint32
	for _, tok := range strings.Fields(s) {
		tok = strings.Trim(tok, "{}()")
		if tok == "" {
			continue
		}
		tok = strings.SplitN(tok, ",", 2)[0]
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(tok), "AS"), 10, 32)
		if err != nil {
			return nil
		}
		if v == 0 {
			continue // AS0 is reserved (RFC 7607)
		}
		out = append(out, uint32(v))
		if len(out) >= 64 {
			break
		}
	}
	return bgpdepth.CompressPath(out)
}

// bgpWatchEventTime parses a wire timestamp off the BMP store.
//
// It distinguishes the two cases the naive `t, _ :=` conflated (§5 no ignored
// errors, §10 no silent failures):
//
//   - EMPTY is legitimate and expected on the fields the store declares
//     omitempty (a peer we have never seen a Peer Up/Down for has no
//     changed_at). ok=true with a zero time: nothing went wrong.
//   - NON-EMPTY but unparseable is a real fault in the feed. ok=false, and the
//     caller COUNTS it and reports it — a silently zeroed event time makes the
//     evaluator stamp the record with `now`, which re-dates evidence (the
//     log-time standard's "event time is never invented").
func bgpWatchEventTime(raw string) (t time.Time, ok bool) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, true
	}
	parsed, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// bgpWatchPeers reads ONE tenant's BMP peer states. It is nil-safe: with
// FEATURE_BMP off there is no receiver, and the module reports the peer rule as
// not running rather than reporting every peer as healthy.
func (s *server) bgpWatchPeers(_ context.Context, tenant string) ([]bgpwatch.PeerObservation, error) {
	if s.bmpAPI == nil {
		return nil, nil
	}
	store := s.bmpAPI.Store()
	if store == nil {
		return nil, nil
	}
	out := []bgpwatch.PeerObservation{}
	badTimes, sample := 0, ""
	for _, sess := range store.Sessions(tenant, false) {
		for _, p := range sess.Peers {
			changed, ok := bgpWatchEventTime(p.ChangedAt)
			if !ok {
				badTimes++
				if sample == "" {
					sample = p.ChangedAt
				}
			}
			out = append(out, bgpwatch.PeerObservation{
				DeviceID: sess.DeviceID, SessionID: sess.ID, Peer: p.Address,
				PeerAS: p.AS, State: p.State, Reason: p.DownReason, ChangedAt: changed,
			})
		}
	}
	// ONE bounded line per call, not one per row: a broken feed must be visible
	// without becoming the log volume it is reporting on.
	if badTimes > 0 {
		logWarn("bgp-watch", "BMP peer records carried an unparseable transition time — those peers are evaluated with NO transition time, so a peer-down event is stamped at evaluation time rather than when it happened",
			map[string]any{"peers": badTimes, "sample": scrubLogValue(truncateUTF8(sample, 64))})
	}
	return out, nil
}

// bgpWatchSightings screens ONE tenant's recently observed prefixes for bogons.
// Two sources, both already tenant-scoped by their own store: the BMP update
// ring and the near-live RIPEstat feed ring. Peek (not Page) is used for the
// feed so a background pass cannot keep a poller alive that nobody is reading.
func (s *server) bgpWatchSightings(_ context.Context, tenant string) ([]bgpwatch.PrefixSighting, error) {
	out := []bgpwatch.PrefixSighting{}
	if s.bmpAPI != nil {
		if store := s.bmpAPI.Store(); store != nil {
			badTimes, sample := 0, ""
			for _, u := range store.Updates(tenant, false, bmp.UpdateFilter{Limit: bgpWatchSightingLimit}) {
				at, ok := bgpWatchEventTime(u.At)
				if !ok {
					badTimes++
					if sample == "" {
						sample = u.At
					}
				}
				out = append(out, bgpwatch.PrefixSighting{
					Prefix: u.Prefix, Peer: u.Peer, Source: "bmp", At: at,
				})
			}
			// The store always stamps `at`, so unlike changed_at above there is
			// no legitimate empty here: any miss is a fault worth reporting.
			if badTimes > 0 {
				logWarn("bgp-watch", "BMP update records carried an unparseable observation time — those bogon sightings are recorded at evaluation time rather than when they were seen",
					map[string]any{"updates": badTimes, "sample": scrubLogValue(truncateUTF8(sample, 64))})
			}
		}
	}
	if s.bgpFeed != nil {
		for _, u := range s.bgpFeed.Peek(tenant, bgpWatchSightingLimit) {
			out = append(out, bgpwatch.PrefixSighting{
				Prefix: u.Prefix, Peer: u.Peer, Origin: u.Origin, Source: "feed", At: u.Time,
			})
		}
	}
	return out, nil
}

// bgpWatchAnnotateWatchlist adds the incident class per watched prefix to the
// watchlist response (tracker #5). It is the ONLY place the Prefixes view gets
// its verdicts, so the page and the pager can never disagree: both read what
// the one classifier produced.
//
// Honest when off: with no evaluator the response carries a NOTE instead of an
// empty incident map — "we are not evaluating" and "nothing is wrong" are
// different answers (§10). A cross-tenant reader is annotated with nothing:
// incidents are per-tenant data and there is no wildcard read.
func (s *server) bgpWatchAnnotateWatchlist(out map[string]any, tenant string, cross bool) {
	if s.bgpWatchEval == nil {
		out["incidents_note"] = "Incident classification is off. Set " + bgpwatch.EnvFeatureFlag +
			"=true to run the watchlist evaluator. No incident here means NOT EVALUATED, not healthy."
		return
	}
	if cross || normTenant(tenant) == "" || tenant == TenantGlobal {
		out["incidents_note"] = "Select a tenant to see its incident classes (they are per-tenant data)."
		return
	}
	incidents, err := s.bgpWatchEval.Incidents(tenant)
	if err != nil {
		out["incidents_note"] = "Incident classes are unavailable for this tenant right now."
		return
	}
	byPrefix := make(map[string]bgpwatch.Incident, len(incidents))
	for _, inc := range incidents {
		byPrefix[inc.Prefix] = inc
	}
	out["incidents"] = byPrefix
	out["incidents_status"] = s.bgpWatchEval.Status(tenant)
}
