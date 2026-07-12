package pathgraph

import (
	"fmt"
	"time"
)

// spine.go — §7: the backend returns an ORDERED SPINE. The UI is a dumb layout of
// this structure: it MUST NOT compute hop order, MUST NOT lay out from node degree,
// and MUST NOT fall back to a star. Hop order is DATA (PathHop.hop_index), decided
// here, on the server, from the measurement.
//
// Boundaries (LAN / SD-WAN / CARRIER / CLOUD) are computed SERVER-SIDE too, from
// the resolved endpoint kinds and seam membership — never from a client-side
// heuristic over labels.

// §5 edge types.
const (
	EdgePathHasHop        = "PATH_HAS_HOP"
	EdgeHopResolvesTo     = "HOP_RESOLVES_TO"
	EdgeCrossesSeam       = "CROSSES_SEAM"
	EdgeTerminatesAt      = "TERMINATES_AT_ENDPOINT"
	EdgeEndpointHostedOn  = "ENDPOINT_HOSTED_ON"
	EdgeServiceExposedBy  = "SERVICE_EXPOSED_BY_ENDPOINT"
	EdgeEvidenceSupports  = "EVIDENCE_SUPPORTS"
	EdgeEvidenceContra    = "EVIDENCE_CONTRADICTS"
	EdgeEvidenceMissing   = "EVIDENCE_MISSING"
	branchProbeMetric     = "PROBE_METRIC"
	branchCandidateOnly   = "CANDIDATE_ONLY" // rank 7: a lead, explicitly NOT an edge
	boundaryLAN           = "LAN"
	boundarySDWAN         = "SD-WAN"
	boundaryCarrier       = "CARRIER"
	boundaryCloud         = "CLOUD"
	boundaryUnknownLabel  = "UNKNOWN"
	timestampLayoutRFC333 = time.RFC3339
)

// Evidence is the §5/§7 evidence block every node and edge must be able to state.
// "An edge that cannot state its evidence is not rendered."
type Evidence struct {
	Ref        string `json:"ref"`
	Method     string `json:"method"`
	Confidence string `json:"confidence"`
	ObservedAt string `json:"observed_at"`
	DataClass  string `json:"data_class"`
}

// SpineNode is one ordered element of the spine (§7).
type SpineNode struct {
	Index          int      `json:"index"`
	Kind           string   `json:"kind"`
	Label          string   `json:"label"`
	Address        string   `json:"address,omitempty"`
	Boundary       string   `json:"boundary"`
	EntityRef      string   `json:"entity_ref,omitempty"`
	State          string   `json:"state"`
	SeamID         string   `json:"seam_id,omitempty"`
	Transformation string   `json:"transformation,omitempty"`
	// RepeatCount > 1 means this node stands for that many CONSECUTIVE measured
	// TTLs with the identical answer (same address, or the same silence). Nothing
	// is dropped — the run is stated as a count instead of drawn as a ladder: a
	// path dying at a gateway answers every remaining TTL from the same box.
	RepeatCount int      `json:"repeat_count,omitempty"`
	Evidence    Evidence `json:"evidence"`
	// CandidateRef is surfaced for the operator, never used to build an edge (§3
	// rank 7). It is deliberately visible: an honest "this NAME looks related" beats
	// a silent false edge.
	CandidateRef string `json:"candidate_ref,omitempty"`
}

// SpineEdge is a typed edge between two spine indices (§5/§7).
type SpineEdge struct {
	From           int      `json:"from"`
	To             int      `json:"to"`
	Type           string   `json:"type"`
	SeamID         string   `json:"seam_id,omitempty"`
	Transformation string   `json:"transformation,omitempty"`
	Evidence       Evidence `json:"evidence"`
}

// Boundary groups a contiguous index range for the renderer (§7).
type Boundary struct {
	Name string `json:"name"`
	From int    `json:"from"`
	To   int    `json:"to"`
}

// EvidenceBranch is evidence that hangs OFF the spine (§7): metrics, resolution
// edges, inferred cloud-route support, honest absences, rank-7 candidates.
type EvidenceBranch struct {
	Type      string   `json:"type"`
	Index     int      `json:"index"`
	Class     string   `json:"class,omitempty"`
	EntityRef string   `json:"entity_ref,omitempty"`
	Note      string   `json:"note,omitempty"`
	RTTms     float64  `json:"rtt_ms,omitempty"`
	LossPct   float64  `json:"loss_pct,omitempty"`
	Evidence  Evidence `json:"evidence"`
}

// Spine is the §7 payload. It is what GET /api/rca/{correlation_id}/path returns
// and what rides inside the RCA read model.
type Spine struct {
	CorrelationID    string           `json:"correlation_id,omitempty"`
	ObservationID    string           `json:"observation_id"`
	PathID           string           `json:"path_id"`
	Method           string           `json:"method"`
	VantageID        string           `json:"vantage_id"`
	Status           string           `json:"status"`
	ObservedAt       string           `json:"observed_at"`
	DataClass        string           `json:"data_class"`
	Stale            bool             `json:"stale"`
	AnchorsLive      bool             `json:"anchors_live_verdict"`
	ContractVersion  int              `json:"contract_version"`
	Spine            []SpineNode      `json:"spine"`
	Edges            []SpineEdge      `json:"edges"`
	Boundaries       []Boundary       `json:"boundaries"`
	EvidenceBranches []EvidenceBranch `json:"evidence_branches"`
}

// ServiceTail is the application node that terminates the spine (§10's "AWS
// application"). It exists ONLY when a rank 2/4 binding produced it — there is no
// name-similarity path to this node.
type ServiceTail struct {
	Service     string
	EntityRef   string
	Method      string // MethodEndpointBinding | MethodAppBinding — nothing else is admissible
	Confidence  string
	EvidenceRef string
	ObservedAt  time.Time
	DataClass   string
}

// SeamHint carries seam membership learned from THIS path's most recent COMPLETE
// observation, for a partial run whose terminal hop is a shared seam endpoint. A
// dying path never shows the seam's far side, so the normal on-path disambiguation
// (path_ingest.transformAt) cannot stamp it — exactly when the NOC needs the seam
// most. The hint is honest: it names its evidence (the prior observation) and is
// rendered as INFERRED support, never as an asserted crossing.
type SeamHint struct {
	SeamID         string
	Transformation string
	EvidenceRef    string // the prior complete observation's provenance
	ObservedAt     time.Time
	DataClass      string
}

// SpineInput is everything the builder needs. The caller (the API layer) supplies
// the immutable observation, its ORDERED hops (already resolved via §3), the client
// endpoint that the path starts at, and — only if a rank 2/4 binding produced one —
// the service tail.
type SpineInput struct {
	CorrelationID string
	Observation   PathObservation
	Hops          []PathHop // ordered by hop_index; missing hops PRESERVED
	Client        Endpoint
	Service       *ServiceTail
	// Supporting carries the rank-6 inferred relations keyed by hop index (1-based),
	// so a cloud route table can EXPLAIN an observed hop without asserting it.
	Supporting map[int][]SupportingRel
	// SeamHint (optional) annotates the terminal responding hop of a PARTIAL
	// observation with the seam this path is known (from its own history) to cross
	// there. Ignored for complete observations and for hops that already carry a
	// seam of their own.
	SeamHint *SeamHint
	// SessionSourceAvailable=false makes the NAT blind spot an explicit evidence
	// gap instead of a silent absence (§4/§8).
	SessionSourceAvailable bool
	Now                    time.Time
	Freshness              time.Duration
}

// BuildSpine turns an immutable observation + its ordered hops into the §7 payload.
// Pure and deterministic: same input, same bytes.
func BuildSpine(in SpineInput) Spine {
	obs := in.Observation
	stale := obs.Stale(in.Now, in.Freshness)
	out := Spine{
		CorrelationID:   in.CorrelationID,
		ObservationID:   obs.ObservationID,
		PathID:          obs.PathID,
		Method:          obs.Method,
		VantageID:       obs.VantageID,
		Status:          obs.Status,
		ObservedAt:      ts(obs.ObservedAt),
		DataClass:       obs.DataClass,
		Stale:           stale,
		ContractVersion: ContractVersion,
		// §1 + §8: only a fresh, LIVE observation may anchor a live verdict. A stale
		// or synthetic/replay/lab run can support, contradict or illustrate — never
		// confirm. The backend states this; the UI does not get to decide it.
		AnchorsLive:      obs.IsLive() && !stale,
		Spine:            []SpineNode{},
		Edges:            []SpineEdge{},
		Boundaries:       []Boundary{},
		EvidenceBranches: []EvidenceBranch{},
	}

	// index 0 — the client / vantage the measurement started from.
	out.Spine = append(out.Spine, SpineNode{
		Index: 0, Kind: orKind(in.Client.Kind, KindClient), Label: label(in.Client.Address, in.Client.ResolvedEntityRef),
		Address: in.Client.Address, EntityRef: in.Client.ResolvedEntityRef, State: HopResponding,
		Evidence: Evidence{
			Ref: in.Client.EvidenceRef, Method: methodOr(in.Client.ResolutionMethod, obs.Method),
			Confidence: orConf(in.Client.Confidence), ObservedAt: ts(obs.ObservedAt), DataClass: obs.DataClass,
		},
	})

	// hops 1..n — ORDERED, missing hops preserved as explicit unknown segments.
	// Consecutive TTLs with the IDENTICAL answer (same responding address, or the
	// same silence) are folded into ONE node carrying repeat_count. A dying path
	// answers every remaining TTL from the drop point, and a 28-rung ladder of one
	// box HIDES the fault it proves; the fold states the same facts as a count
	// (TTL range in the branch note) — nothing dropped, nothing bridged.
	for _, run := range collapseHops(in.Hops) {
		h := run.first
		idx := len(out.Spine)
		n := SpineNode{
			Index: idx, Kind: hopKind(h), Label: hopLabel(h), Address: h.ObservedAddress,
			EntityRef: h.ResolvedEntityRef, State: h.State, SeamID: h.SeamID,
			Transformation: nonNoneTransform(h.Transformation), CandidateRef: h.CandidateRef,
			Evidence: Evidence{
				Ref: h.EvidenceRef, Method: obs.Method, Confidence: orConf(h.Confidence),
				ObservedAt: ts(h.ObservedAt), DataClass: dataClassOr(h.DataClass, obs.DataClass),
			},
		}
		if run.count > 1 {
			n.RepeatCount = run.count
		}
		out.Spine = append(out.Spine, n)

		// off-spine evidence for this hop.
		if h.State == HopResponding {
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: branchProbeMetric, Index: idx, Class: ClassObserved,
				RTTms: h.RTTms, LossPct: h.LossPct, Evidence: n.Evidence,
			})
			if run.count > 1 {
				out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
					Type: EdgeEvidenceMissing, Index: idx, Class: ClassObserved,
					Note: fmt.Sprintf("TTL %d–%d were all answered by %s — packets did not progress past this node",
						h.HopIndex, run.lastTTL, label(h.ObservedAddress, h.ResolvedEntityRef)),
					Evidence: n.Evidence,
				})
			}
		} else {
			// §2.4/§8: an honest absence IS an edge. The unknown segment is recorded,
			// not bridged.
			note := fmt.Sprintf("hop %d did not respond (%s) — segment unknown, not bridged", h.HopIndex, h.State)
			if run.count > 1 {
				note = fmt.Sprintf("hops %d–%d did not respond (%s) — segment unknown, not bridged", h.HopIndex, run.lastTTL, h.State)
			}
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: EdgeEvidenceMissing, Index: idx, Class: ClassObserved,
				Note:     note,
				Evidence: n.Evidence,
			})
		}
		if h.ResolvedEntityRef != "" && Authoritative(h.ResolutionMethod) {
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: EdgeHopResolvesTo, Index: idx, Class: ClassObserved, EntityRef: h.ResolvedEntityRef,
				Note: "resolved by " + h.ResolutionMethod, Evidence: n.Evidence,
			})
		}
		if h.CandidateRef != "" {
			// Rank 7 is shown as a LEAD and labelled as such. It is not in edges[].
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: branchCandidateOnly, Index: idx, Class: ClassCandidate, EntityRef: "",
				Note:     "name/token match to " + h.CandidateRef + " — candidate only, never an authoritative edge (§3 rank 7)",
				Evidence: Evidence{Ref: h.EvidenceRef, Method: MethodTokenSimilarity, Confidence: ConfCandidate, ObservedAt: ts(h.ObservedAt), DataClass: dataClassOr(h.DataClass, obs.DataClass)},
			})
		}
		for _, sup := range in.Supporting[h.HopIndex] {
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: EdgeEvidenceSupports, Index: idx, Class: ClassInferred, EntityRef: sup.Ref,
				Note: supNote(sup),
				Evidence: Evidence{
					Ref: sup.EvidenceRef, Method: sup.Method, Confidence: sup.Confidence,
					ObservedAt: ts(h.ObservedAt), DataClass: sup.DataClass,
				},
			})
		}
	}

	// A partial/failed run means the DESTINATION NEVER ANSWERED: say so, on the
	// last hop that did. This is the §8 honest terminal statement — the path dies
	// here, in this run, at this node.
	if obs.Status != StatusComplete {
		if last := lastResponding(out.Spine); last > 0 {
			n := &out.Spine[last]
			// The seam hint: this path's own last COMPLETE observation stamps the
			// seam its terminal hop sits on. Applied only when the hop has none of
			// its own — never overwritten, never asserted as a crossing edge.
			if in.SeamHint != nil && in.SeamHint.SeamID != "" && n.SeamID == "" {
				n.SeamID = in.SeamHint.SeamID
				if n.Transformation == "" {
					n.Transformation = nonNoneTransform(in.SeamHint.Transformation)
				}
				out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
					Type: EdgeEvidenceSupports, Index: n.Index, Class: ClassInferred,
					Note: "seam " + in.SeamHint.SeamID + " known from this path's last complete observation — the current run dies at its near endpoint; the crossing itself is not asserted",
					Evidence: Evidence{
						Ref: in.SeamHint.EvidenceRef, Method: "prior_complete_observation",
						Confidence: ConfCandidate, ObservedAt: ts(in.SeamHint.ObservedAt),
						DataClass: dataClassOr(in.SeamHint.DataClass, obs.DataClass),
					},
				})
			}
			out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
				Type: EdgeEvidenceMissing, Index: n.Index, Class: ClassObserved,
				Note:     "destination never responded in this run (" + obs.Status + ") — the measured path terminates at this node",
				Evidence: n.Evidence,
			})
		}
	}

	// the service tail — ONLY from a rank 2/4 binding (§3/§10). On a partial or
	// failed run its state is MISSING: the binding says which application lives at
	// the destination; it does not say the destination answered — this run proved
	// it did not.
	if in.Service != nil && Authoritative(in.Service.Method) {
		idx := len(out.Spine)
		tailState := HopResponding
		if obs.Status != StatusComplete {
			tailState = HopMissing
		}
		out.Spine = append(out.Spine, SpineNode{
			Index: idx, Kind: KindApplication, Label: in.Service.Service, EntityRef: in.Service.EntityRef,
			State: tailState,
			Evidence: Evidence{
				Ref: in.Service.EvidenceRef, Method: in.Service.Method, Confidence: orConf(in.Service.Confidence),
				ObservedAt: ts(in.Service.ObservedAt), DataClass: dataClassOr(in.Service.DataClass, obs.DataClass),
			},
		})
	}

	out.Boundaries = boundaries(out.Spine)
	// Boundary is a per-node projection of the same computation — assigned here so
	// a node and its group can never disagree.
	for i := range out.Spine {
		out.Spine[i].Boundary = boundaryOf(out.Boundaries, i)
	}
	out.Edges = buildEdges(out.Spine)

	// The honest NAT/session blind spot (§4): if no session source exists, say so
	// once, on the terminal endpoint, rather than implying the path has no NAT.
	if !in.SessionSourceAvailable && len(out.Spine) > 0 {
		last := len(out.Spine) - 1
		out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
			Type: EdgeEvidenceMissing, Index: last, Class: ClassNone,
			Note: "no flow/NAT session source is wired (§3 rank 5 unavailable): a translation on this path could not be stitched, only tunnel transformations at modelled seams are known",
			Evidence: Evidence{
				Ref: obs.ProvenanceID, Method: obs.Method, Confidence: ConfUnknown,
				ObservedAt: ts(obs.ObservedAt), DataClass: obs.DataClass,
			},
		})
	}
	// TERMINATES_AT_ENDPOINT (§5): the observation terminates at the last spine node.
	if len(out.Spine) > 0 {
		last := out.Spine[len(out.Spine)-1]
		out.EvidenceBranches = append(out.EvidenceBranches, EvidenceBranch{
			Type: EdgeTerminatesAt, Index: last.Index, Class: ClassObserved, EntityRef: last.EntityRef,
			Note: "observation terminates at this endpoint", Evidence: last.Evidence,
		})
	}
	return out
}

// buildEdges walks consecutive spine indices and types each edge per §5. The edge
// carries the evidence of the node it enters (the observation that established it);
// an edge with no evidence is never emitted.
func buildEdges(nodes []SpineNode) []SpineEdge {
	out := []SpineEdge{}
	for i := 0; i+1 < len(nodes); i++ {
		a, b := nodes[i], nodes[i+1]
		e := SpineEdge{From: a.Index, To: b.Index, Type: EdgePathHasHop, Evidence: b.Evidence}
		switch {
		case b.Kind == KindApplication:
			// The app↔endpoint edge. Its evidence is the rank 2/4 binding — provably
			// NOT a token overlap between the app name and a seam endpoint.
			e.Type = EdgeServiceExposedBy
		case seamCrossing(a, b):
			e.Type = EdgeCrossesSeam
			e.SeamID = firstNonEmpty(a.SeamID, b.SeamID)
			e.Transformation = TransformTunnelIngress
		}
		if e.Evidence.Ref == "" {
			continue // §5: an edge that cannot state its evidence is not rendered.
		}
		out = append(out, e)
	}
	return out
}

// seamCrossing reports whether the a→b edge crosses an ownership seam. BOTH ends
// must be members of the SAME seam: that is what "the packet crossed this seam"
// means, and it is a fact the seam inventory states (its endpoints), not something
// derived from address arithmetic or from a boundary label changing.
//
// Being adjacent to a seam member is NOT a crossing — the LAN-gateway→WAN-edge hop
// sits inside the enterprise on both ends even though the boundary LABEL changes
// there (LAN → SD-WAN). An earlier version of this function typed that edge as a
// seam crossing because one end carried a seam id and the boundaries differed; it
// claimed a tunnel where there was none. Strictness here is the difference between
// a modelled transformation and an invented one.
//
// Consequence, stated honestly: if only ONE side of a seam responds to the trace
// (the far end is filtered), no edge is typed CROSSES_SEAM — we cannot say WHICH
// edge crossed it. The hop still carries its seam_id and its transformation, so the
// seam is visible; the crossing edge is not asserted. That is the correct answer to
// "we don't know", and it is why the missing hop is preserved rather than bridged.
func seamCrossing(a, b SpineNode) bool {
	return a.SeamID != "" && a.SeamID == b.SeamID && a.Boundary != b.Boundary
}

// boundaries computes the LAN / SD-WAN / CARRIER / CLOUD grouping SERVER-SIDE from
// the resolved kinds. Deterministic, and the only place the grouping is decided.
func boundaries(nodes []SpineNode) []Boundary {
	lastLAN, wanIdx, cloudStart := -1, -1, -1
	for i, n := range nodes {
		switch n.Kind {
		case KindClient, KindLANGateway:
			lastLAN = i
		case KindWANEdge:
			if wanIdx < 0 {
				wanIdx = i
			}
		case KindNVA, KindCloudEdge, KindAppEndpoint, KindServiceEndpoint, KindApplication:
			if cloudStart < 0 {
				cloudStart = i
			}
		}
	}
	out := []Boundary{}
	if lastLAN >= 0 {
		out = append(out, Boundary{Name: boundaryLAN, From: 0, To: lastLAN})
	}
	if wanIdx >= 0 {
		out = append(out, Boundary{Name: boundarySDWAN, From: wanIdx, To: wanIdx})
	}
	if wanIdx >= 0 && cloudStart > wanIdx {
		// The carrier segment is what lies BETWEEN the WAN edge and the cloud edge —
		// the part we do not own and often cannot see.
		out = append(out, Boundary{Name: boundaryCarrier, From: wanIdx, To: cloudStart})
	}
	if cloudStart >= 0 {
		out = append(out, Boundary{Name: boundaryCloud, From: cloudStart, To: len(nodes) - 1})
	}
	return out
}

// boundaryOf projects the node's own boundary label from the computed ranges. The
// CLOUD range wins over CARRIER where they touch (the cloud edge is IN the cloud);
// SD-WAN wins over CARRIER at the WAN edge, for the same reason.
func boundaryOf(bs []Boundary, i int) string {
	name := ""
	for _, b := range bs {
		if i < b.From || i > b.To {
			continue
		}
		switch b.Name {
		case boundaryCloud:
			return boundaryCloud
		case boundarySDWAN:
			name = boundarySDWAN
		case boundaryLAN:
			if name == "" {
				name = boundaryLAN
			}
		case boundaryCarrier:
			if name == "" {
				name = boundaryCarrier
			}
		}
	}
	if name == "" {
		return boundaryUnknownLabel
	}
	return name
}

// ── small helpers ────────────────────────────────────────────────────────────

// hopRun is a maximal run of consecutive TTLs with the identical answer.
type hopRun struct {
	first   PathHop
	count   int
	lastTTL int
}

// collapseHops folds consecutive hops that gave the identical answer — the same
// responding address, or the same silence — into one run. Order is preserved;
// alternating addresses (a real routing loop) are NOT folded.
func collapseHops(hops []PathHop) []hopRun {
	out := make([]hopRun, 0, len(hops))
	for _, h := range hops {
		if n := len(out); n > 0 && sameAnswer(out[n-1].first, h) {
			out[n-1].count++
			out[n-1].lastTTL = h.HopIndex
			continue
		}
		out = append(out, hopRun{first: h, count: 1, lastTTL: h.HopIndex})
	}
	return out
}

func sameAnswer(a, b PathHop) bool {
	if a.State != b.State {
		return false
	}
	if a.State == HopResponding {
		return a.ObservedAddress != "" && a.ObservedAddress == b.ObservedAddress
	}
	return true // two silent TTLs are the same absence
}

// lastResponding returns the index (in spine order) of the last RESPONDING hop
// node, excluding the client at index 0; -1 when there is none.
func lastResponding(nodes []SpineNode) int {
	for i := len(nodes) - 1; i > 0; i-- {
		if nodes[i].State == HopResponding {
			return i
		}
	}
	return -1
}

func hopKind(h PathHop) string {
	if h.Kind != "" {
		return h.Kind
	}
	if h.State != HopResponding {
		return KindUnknown
	}
	if h.ResolvedEntityRef == "" {
		return KindUnknown // unresolved stays unknown — never guessed (§8)
	}
	return KindTransit
}

func hopLabel(h PathHop) string {
	if h.State != HopResponding {
		return fmt.Sprintf("unknown hop %d", h.HopIndex)
	}
	return label(h.ObservedAddress, h.ResolvedEntityRef)
}

func label(addr, ref string) string {
	if ref != "" {
		return ref
	}
	if addr != "" {
		return addr
	}
	return "unknown"
}

func nonNoneTransform(t string) string {
	if t == TransformNone {
		return ""
	}
	return t
}

func supNote(s SupportingRel) string {
	return fmt.Sprintf("cloud route %s → %s (%s) via %s — INFERRED (control plane): explains the observed hop, does not assert it",
		s.Destination, s.Ref, s.ToKind, s.RouteTable)
}

func orKind(k, def string) string {
	if k == "" {
		return def
	}
	return k
}

func orConf(c string) string {
	if c == "" {
		return ConfUnknown
	}
	return c
}

func methodOr(m, def string) string {
	if m == "" || m == MethodUnresolved {
		return def
	}
	return m
}

func dataClassOr(c, def string) string {
	if c == "" {
		return def
	}
	return c
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timestampLayoutRFC333)
}
