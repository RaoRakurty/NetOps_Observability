package experience

// flow.go — the PASSIVE-FLOW evidence producer: the second anchor-capable
// experience evidence class (tracker 252, design of record §M.5 Tier 0).
//
// WHY THIS EXISTS
// ---------------
// Confirmation is a property of the EVIDENCE, not of the analysis: the
// independence rule (evidence.go, and its Python twin src/correlation/
// verdicts.py) needs two DIFFERENT anchor-capable modality classes from two
// different observers. Until this file, Correlix produced exactly one —
// `active_probe`, from the synthetic prober — so a live tenant could honestly
// reach `suspected` and never `confirmed`. Flow records are observed on the
// wire by the exporter, not by our prober, so they are a genuinely different
// instrument with a genuinely different vantage, and `passive_flow` is
// anchor-capable in BOTH graders (see the anchor-capability note below).
//
// WHAT THE FLOW LANE ACTUALLY CARRIES (verified, not assumed)
// -----------------------------------------------------------
// The design of record calls this class "flow-derived application response
// time". `netops.flows` DOES NOT CARRY A TIMING COLUMN. Its columns are, in
// full (deployment/docker/clickhouse/init.sql, and confirmed against the live
// table): ts, time_received_ns, sampler_address, src_addr, dst_addr, src_port,
// dst_port, proto, bytes, packets, in_if, out_if, src_as, dst_as,
// sampling_rate, vlan_id, tcp_flags, flow_type, tenant_id.
//
// There is no server-response-time, no client/server network latency and no
// retransmit counter, because goflow2 exports none and the ClickHouse schema
// declares none. So this producer measures the one wire-observable EXPERIENCE
// outcome the lane genuinely carries — TCP conversations that were ABORTED
// (the RST control bit, IPFIX IE6 / NetFlow TCP_FLAGS) — and reports
// responsiveness as NOT MEASURED, naming the missing columns. Deriving a
// "response time" from bytes and packets would be exactly the confident guess
// this product exists to replace.
//
// THE EXPORTER-SILENCE TRAP (the honesty rule this file turns into code)
// ---------------------------------------------------------------------
// `tcp_flags` defaults to 0 and a great many exporters never populate it. Zero
// resets out of a thousand flows therefore means one of two OPPOSITE things:
// "nothing was aborted" or "this exporter does not export tcpControlBits". A
// reset ratio is computed ONLY from flows that carry a non-zero tcp_flags
// value; when none does, the subject is NOT MEASURED and the Data Health
// surface says which IPFIX field the exporter would have to send. An absent
// instrument must never render as a healthy reading.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/dem"
)

// Thresholds. Declared as named constants so the docs can quote the numbers and
// a reviewer can argue with them in one place instead of in six call sites.
const (
	// MinFlowSamples is how many flag-bearing TCP flows a subject needs before a
	// reset RATIO is a measurement rather than an anecdote. Below it the subject
	// reports not-measured, never "0% — healthy".
	MinFlowSamples = 20

	// FlowResetRatioThresholdPct is the share of flag-bearing TCP conversations
	// that must have been aborted before the wire is SAYING something. Chosen
	// deliberately above the background rate of ordinary client aborts (a user
	// closing a tab, a load balancer recycling an idle connection), because a
	// threshold at the noise floor produces an evidence item on every subject
	// every window, and evidence that is always present carries no information.
	FlowResetRatioThresholdPct = 5.0

	// MaxFlowSubjects bounds how many subjects one assembly will ask the flow
	// store about (§9: every query is bounded). It is the catalogue's own bound,
	// so a tenant cannot widen the query by declaring more targets.
	MaxFlowSubjects = dem.MaxScoredTargets

	// MaxFlowEndpointsPerSubject bounds the addresses folded into one subject.
	MaxFlowEndpointsPerSubject = 32
)

// FlowEndpoint is one server-side address (and optionally port) a subject's
// traffic is identified by. Addr is an IP LITERAL: flow records carry addresses,
// so a target declared by hostname contributes no endpoint and its subject says
// so rather than silently measuring nothing.
type FlowEndpoint struct {
	Addr string `json:"addr"`
	// Port is the server port. 0 = any port on Addr, which is the honest answer
	// for an ICMP target: it names a host, not a service.
	Port int `json:"port,omitempty"`
}

// FlowSubject is one DEM subject the flow lane is asked about.
//
// Subject is the DEM_DATA_MODEL identity `<app>@<site>` — the SAME identity
// model the synthetic source writes, not a new one. Kind is dem.KindFlowApp and
// Source is dem.SourceFlow, both of which the data model reserved for exactly
// this producer before it existed.
type FlowSubject struct {
	Subject string `json:"subject"`
	App     string `json:"app"`
	Site    string `json:"site,omitempty"`
	// TargetIDs are the catalogue targets this subject was folded from. Carried
	// so provenance can name the declaration a measurement came from.
	TargetIDs []string       `json:"target_ids,omitempty"`
	Endpoints []FlowEndpoint `json:"endpoints"`
}

// FlowStats is the flow store's answer for one subject over one window. Every
// field is a COUNT of records, not a derived rate: the maths is done here, in
// Go, where it is unit-tested, rather than in a SQL expression nothing can test.
type FlowStats struct {
	Subject string `json:"subject"`
	// Flows is every flow record touching the subject's endpoints.
	Flows int64 `json:"flows"`
	// TCPFlows is the subset with proto = 6.
	TCPFlows int64 `json:"tcp_flows"`
	// FlagBearingFlows is the subset of TCPFlows whose tcp_flags is non-zero —
	// i.e. the subset for which the exporter actually reported control bits.
	// THE DENOMINATOR OF THE RESET RATIO. Zero here means "the exporter is
	// silent about TCP flags", never "nothing was reset".
	FlagBearingFlows int64 `json:"flag_bearing_flows"`
	// ResetFlows is the subset of FlagBearingFlows carrying the RST bit (0x04).
	ResetFlows int64 `json:"reset_flows"`

	Bytes   int64 `json:"bytes"`
	Packets int64 `json:"packets"`

	// Exporters are the distinct sampler_address values that reported. They are
	// the OBSERVERS: a flow observation's vantage is the exporter, which is what
	// makes it independent of the prober.
	Exporters []string `json:"exporters,omitempty"`

	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

// FlowQuerier answers the flow-record aggregate for one tenant's subjects.
//
// It is an INTERFACE for the same reason dem.Querier is: the reasoning in this
// package must be testable without ClickHouse, and the storage adapter must be
// the only thing that knows about SQL, tenant scoping settings and the untagged
// -row narrowing the flows row policy requires. A nil FlowQuerier is LEGAL and
// HONEST — the source then reports "off: no flow producer is wired", which is a
// different sentence from "no flows were seen".
type FlowQuerier interface {
	// FlowStats returns one entry per subject that had at least one matching
	// flow record. A subject with no flows is ABSENT from the result (the
	// caller renders not-measured); it is never returned as a zero row, because
	// a zero row and an absent row mean different things.
	//
	// The implementation MUST scope to tenant fail-closed. An error is an
	// error: it is reported, never folded into "no flows".
	FlowStats(ctx context.Context, tenant string, subjects []FlowSubject, start, end time.Time) ([]FlowStats, error)
}

// FlowSubjectID is the DEM subject identity for a flow-derived measurement:
// `<app>@<site>` per DEM_DATA_MODEL §2. A subject with no site is the app on its
// own — an app measured from nowhere in particular is still one subject, and
// inventing a site label for it would put a fact under a place nobody declared.
func FlowSubjectID(app, site string) string {
	app = strings.ToLower(strings.TrimSpace(app))
	site = strings.ToLower(strings.TrimSpace(site))
	if app == "" {
		return ""
	}
	if site == "" {
		return app
	}
	return app + "@" + site
}

// FlowIdentity projects a flow subject onto the source-agnostic DEM identity, so
// a flow measurement and a synthetic measurement of the same app at the same
// site are the same shape on the same series with a different `source` label.
func (s FlowSubject) FlowIdentity(tenant string) dem.Identity {
	return dem.Identity{
		Tenant: tenant, Subject: s.Subject, Kind: dem.KindFlowApp,
		Site: s.Site, App: s.App, Source: dem.SourceFlow,
	}
}

// FlowSubjectsFor folds a tenant's declared catalogue into the flow subjects the
// flow lane can be asked about.
//
// THE SUBJECT MAPPING, stated plainly: a flow subject is (app, site), its
// endpoints are the IP literals its targets point at, and BOTH come from the
// existing catalogue. Nothing here invents an identity, resolves a name, or
// guesses a site from an address — there is no subnet→site map in this
// repository, and a producer that invented one would be attributing a
// measurement to a place nobody declared.
//
// A target contributes nothing when it declares no app (there is no subject to
// hang the measurement on), when it is paused (it is deliberately silent), or
// when its host is not an IP literal (flow records carry addresses; resolving a
// name here would measure whatever that name resolves to on THIS host, which is
// not what the user reached).
func FlowSubjectsFor(targets []dem.Target) []FlowSubject {
	type acc struct {
		app, site string
		targets   []string
		endpoints []FlowEndpoint
		seen      map[string]bool
	}
	order := make([]string, 0, len(targets))
	byID := map[string]*acc{}

	for _, t := range targets {
		if t.Paused {
			continue
		}
		id := FlowSubjectID(t.App, t.Site)
		if id == "" {
			continue
		}
		ep, ok := flowEndpointOf(t)
		if !ok {
			continue
		}
		a, exists := byID[id]
		if !exists {
			if len(order) >= MaxFlowSubjects {
				continue
			}
			a = &acc{app: strings.TrimSpace(t.App), site: strings.TrimSpace(t.Site), seen: map[string]bool{}}
			byID[id] = a
			order = append(order, id)
		}
		a.targets = append(a.targets, t.ID)
		k := ep.Addr + "/" + strconv.Itoa(ep.Port)
		if !a.seen[k] && len(a.endpoints) < MaxFlowEndpointsPerSubject {
			a.seen[k] = true
			a.endpoints = append(a.endpoints, ep)
		}
	}

	sort.Strings(order)
	out := make([]FlowSubject, 0, len(order))
	for _, id := range order {
		a := byID[id]
		sort.Strings(a.targets)
		sort.SliceStable(a.endpoints, func(i, j int) bool {
			if a.endpoints[i].Addr != a.endpoints[j].Addr {
				return a.endpoints[i].Addr < a.endpoints[j].Addr
			}
			return a.endpoints[i].Port < a.endpoints[j].Port
		})
		out = append(out, FlowSubject{
			Subject: id, App: a.app, Site: a.site,
			TargetIDs: a.targets, Endpoints: a.endpoints,
		})
	}
	return out
}

// flowEndpointOf derives the server-side endpoint a target names, or reports
// that it names none. Only an IP LITERAL qualifies — see FlowSubjectsFor.
func flowEndpointOf(t dem.Target) (FlowEndpoint, bool) {
	host := strings.TrimSpace(t.Host)
	if host == "" {
		return FlowEndpoint{}, false
	}
	port := t.Port
	// http targets carry a URL; tcp targets may carry host:port. Peel both
	// WITHOUT a URL parser: only a bare IP literal is admissible anyway, so the
	// question is just where the literal ends.
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
		if j := strings.IndexAny(host, "/?#"); j >= 0 {
			host = host[:j]
		}
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if n, cerr := strconv.Atoi(p); cerr == nil && n > 0 && n < 65536 {
			host, port = h, n
		}
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		return FlowEndpoint{}, false
	}
	if port < 0 || port > 65535 {
		port = 0
	}
	return FlowEndpoint{Addr: ip.String(), Port: port}, true
}

// FlowReset is the measured abort ratio for one subject, or the honest reason
// there is none. It is a value type so the maths is a table test.
type FlowReset struct {
	Measured bool
	RatioPct float64
	// Samples is the DENOMINATOR actually used — flag-bearing TCP flows, not
	// every flow. A ratio whose denominator is not stated is not a measurement.
	Samples int64
	Reason  string
	Detail  string
}

// ResetRatio grades one subject's flow aggregate.
//
// Three not-measured branches, each with its own sentence, because collapsing
// them into one "no data" is how an exporter misconfiguration gets mistaken for
// a quiet network:
//
//	no TCP flows at all           — nothing of this kind crossed the exporter
//	no flag-bearing TCP flows     — the exporter does not report tcpControlBits
//	too few flag-bearing flows    — a ratio over a handful of flows is noise
func (f FlowStats) ResetRatio() FlowReset {
	switch {
	case f.TCPFlows == 0:
		return FlowReset{Reason: dem.ReasonNoSamples,
			Detail: "no TCP conversation for this subject crossed a flow exporter in this window, so nothing about it was measured on the wire"}
	case f.FlagBearingFlows == 0:
		return FlowReset{Reason: MissingNotSupported,
			Detail: "the flow exporter reported no TCP control bits (IPFIX tcpControlBits / NetFlow TCP_FLAGS) on any of these flows, so aborted conversations cannot be counted — this is an exporter gap, not a healthy reading"}
	case f.FlagBearingFlows < MinFlowSamples:
		return FlowReset{Reason: dem.ReasonNoSamples,
			Detail: fmt.Sprintf("only %d flow records carried TCP control bits, below the %d needed for a ratio to mean anything",
				f.FlagBearingFlows, MinFlowSamples)}
	}
	return FlowReset{
		Measured: true, Samples: f.FlagBearingFlows,
		RatioPct: round2(float64(f.ResetFlows) / float64(f.FlagBearingFlows) * 100),
	}
}

// FlowObserver is the vantage a flow observation was made from. It is the
// EXPORTER, never the prober — which is precisely what makes a flow item and a
// synthetic item two observers and therefore capable of forming an independent
// pair. With several exporters the lowest address names the vantage
// deterministically and the rest are listed in the item's detail.
func FlowObserver(exporters []string) string {
	clean := make([]string, 0, len(exporters))
	seen := map[string]bool{}
	for _, e := range exporters {
		e = strings.TrimSpace(e)
		if e == "" || seen[e] {
			continue
		}
		seen[e] = true
		clean = append(clean, e)
	}
	if len(clean) == 0 {
		return "flow"
	}
	sort.Strings(clean)
	return "flow@" + clean[0]
}

// flowEvidence is THE ADAPTER — the one function assemble.go calls to turn what
// the flow lane measured into evidence this package can reason over.
//
// It produces at most one item per subject:
//
//   - reset ratio ABOVE the threshold → SUPPORTS, modality `passive_flow`,
//     observer `flow@<exporter>`, NO cause class. The absence of a cause class
//     is deliberate and mirrors causeForKind: an aborted conversation says the
//     service stopped completing conversations, not WHY, and an item that names
//     no cause bears on every hypothesis the other evidence raised — which is
//     exactly the corroboration an anchor is for.
//
//   - reset ratio AT or below the threshold → NEUTRAL context. Not a
//     contradiction: an application can degrade badly without ever resetting a
//     connection, and a sampled exporter can miss the resets that did occur.
//     Rendering a weak absence as a refutation would let it veto a strong
//     measurement, and an unattached contradiction bears on EVERY hypothesis
//     (hypothesis.go selectEvidence) — so this one line is the difference
//     between "context" and "nothing can ever be confirmed again".
//
//   - not measured → NOTHING. The absence is carried by Data Health, where it
//     lowers confidence with its reason, rather than by a fabricated item.
func flowEvidence(in AssembleInput) []EvidenceItem {
	if !in.FlowsAvailable {
		return nil
	}
	bySubject := map[string]FlowSubject{}
	for _, s := range in.FlowSubjects {
		bySubject[s.Subject] = s
	}
	stats := append([]FlowStats(nil), in.Flows...)
	sort.SliceStable(stats, func(i, j int) bool { return stats[i].Subject < stats[j].Subject })

	out := make([]EvidenceItem, 0, len(stats))
	for _, st := range stats {
		sub, ok := bySubject[st.Subject]
		if !ok {
			// A row for a subject nobody declared cannot be attributed to an
			// app or a site, so it is dropped rather than rendered under a
			// guessed identity. It still counted towards the source's own
			// "flowing" state in assembleDataHealth.
			continue
		}
		r := st.ResetRatio()
		if !r.Measured {
			continue
		}
		observer := FlowObserver(st.Exporters)
		prov := Provenance{
			Source: SourceFlow, SourceObject: st.Subject, Producer: observer,
			EventAt: flowEventAt(st, in.Now), ObservedAt: flowEventAt(st, in.Now),
			Observation: ObservationObserved, DataClass: DataClassCustomerMetadata,
		}
		detail := fmt.Sprintf("%d of %d TCP conversations carrying control bits were aborted (%d flow records in total, %s reporting). Flow records carry no timing field, so this says nothing about how FAST the service answered.",
			st.ResetFlows, st.FlagBearingFlows, st.Flows,
			plural(len(st.Exporters), "one exporter is", "several exporters are"))

		v, b := r.RatioPct, FlowResetRatioThresholdPct
		if r.RatioPct > FlowResetRatioThresholdPct {
			out = append(out, EvidenceItem{
				ID: "flow-reset-" + st.Subject, TenantID: in.TenantID, Kind: KindServiceHealth,
				Entity: st.Subject, EntityKind: "service",
				Summary: fmt.Sprintf("%.2f%% of TCP conversations with %s were aborted on the wire, against a %.2f%% bar, observed by %s",
					v, flowSubjectLabel(sub), b, observer),
				Detail: detail,
				Value:  &v, Baseline: &b, Unit: "%",
				Stance: StanceSupports, IndependenceGroup: ModalityPassiveFlow, Observer: observer,
				Reliability: DefaultReliability(SourceFlow),
				App:         sub.App, Site: sub.Site, Cohort: Cohort{Site: sub.Site},
				Provenance: prov,
			})
			continue
		}
		out = append(out, EvidenceItem{
			ID: "flow-reset-ok-" + st.Subject, TenantID: in.TenantID, Kind: KindServiceHealth,
			Entity: st.Subject, EntityKind: "service",
			Summary: fmt.Sprintf("%.2f%% of TCP conversations with %s were aborted on the wire, below the %.2f%% bar, observed by %s",
				v, flowSubjectLabel(sub), b, observer),
			Detail: detail + " A low abort rate is context, not a clean bill of health: a service can be unusably slow without ever resetting a connection.",
			Value:  &v, Baseline: &b, Unit: "%",
			Stance: StanceNeutral, IndependenceGroup: ModalityPassiveFlow, Observer: observer,
			Reliability: DefaultReliability(SourceFlow),
			App:         sub.App, Site: sub.Site,
			Provenance: prov,
		})
	}
	return out
}

// flowSubjectLabel is the operator-facing name of a subject.
func flowSubjectLabel(s FlowSubject) string {
	if s.Site == "" {
		return s.App
	}
	return s.App + " at " + s.Site
}

func flowEventAt(st FlowStats, fallback time.Time) time.Time {
	if !st.LastSeen.IsZero() {
		return st.LastSeen.UTC()
	}
	return fallback.UTC()
}

// flowSourceHealth grades the flow source for the Data Health surface.
//
// The four states are four different operator actions, which is why they are
// four sentences and not one:
//
//	off             — no flow store is wired to the experience surface at all
//	off             — nothing is declared that a flow could be attributed to
//	misconfigured   — the flow store did not answer (NOT "no flows")
//	no_data         — subjects are declared and the store answered with nothing
//	flowing         — the wire reported on at least one declared subject
//
// Every branch also states the standing limitation of the lane — no timing
// column, therefore no responsiveness — because a source that is "flowing" and
// still cannot measure half of what the class is named for must say so on the
// surface where an operator reads how much to trust it.
func flowSourceHealth(in AssembleInput, evidenceCount int, last time.Time) SourceHealth {
	const noTiming = "Responsiveness is NOT measured from flow: netops.flows carries no server-response-time, network-latency or retransmit column (no exporter in this deployment sends one), so this source contributes availability-shaped evidence only."

	h := SourceHealth{
		Source: SourceFlow, EventsInWindow: evidenceCount,
		Configured:    in.FlowsConfigured && len(in.FlowSubjects) > 0,
		CoverageTotal: len(in.FlowSubjects),
	}
	if !last.IsZero() {
		t := last.UTC()
		h.LastSeen = &t
	}
	measured := 0
	for _, st := range in.Flows {
		if st.ResetRatio().Measured {
			measured++
		}
	}
	h.CoverageCovered = measured

	switch {
	case !in.FeatureEnabled:
		h.State, h.Detail = StateOff, "experience collection is switched off. "+noTiming
	case !in.FlowsConfigured:
		h.State, h.Detail = StateOff, "no flow store is wired to the experience surface, so the wire is not being read at all. "+noTiming
	case len(in.FlowSubjects) == 0:
		h.State, h.Detail = StateOff, "no declared target names an application AND an IP address, so there is no subject a flow record could be attributed to. "+noTiming
	case in.FlowError != nil:
		h.State, h.Detail = StateMisconfigured, "the flow store did not answer, so we cannot say whether the wire saw anything. "+noTiming
	case len(in.Flows) == 0:
		h.State, h.Detail = StateNoData, "no flow record touched any declared subject in this window. "+noTiming
	case measured == 0:
		h.State, h.Detail = StateNoData, "flow records reached these subjects but none could be graded — see each subject's reason (most often the exporter reports no TCP control bits). "+noTiming
	default:
		h.State, h.Detail = StateFlowing, noTiming
	}
	return h
}
