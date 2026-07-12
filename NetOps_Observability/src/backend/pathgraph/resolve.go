package pathgraph

import (
	"sort"
	"strings"
	"time"
)

// resolve.go — §3 RANKED endpoint & hop resolution. This REPLACES token overlap.
//
// A relationship may become an AUTHORITATIVE graph edge only from ranks 1–5
// (observed). Rank 6 (cloud route tables / Azure UDRs / BGP / SD-WAN policy) is
// INFERRED — supporting/explanatory only. Rank 7 (shared tokens / rDNS / name
// similarity) is CANDIDATE ONLY and may NEVER create an authoritative edge.
//
// The ranking is enforced STRUCTURALLY, not by convention:
//
//	Resolution.EntityRef     ← written only by ranks 1–5
//	Resolution.Supporting    ← rank 6 (inferred relations; explain, never assert)
//	Resolution.CandidateRef  ← rank 7 (a lead for a human; never an edge)
//
// The spine builder (spine.go) reads EntityRef/Authoritative and nothing else, so
// no amount of token overlap between `store-api` and a seam endpoint can produce
// an edge. That is the §10 acceptance requirement, made unfalsifiable by types.

// Resolution methods, named for the rank that produced them.
const (
	MethodResourceIdentity = "resource_identity"    // rank 1 — same immutable resource_id
	MethodEndpointBinding  = "endpoint_binding"     // rank 2 — cloud NIC/ENI, agent reg, orchestration
	MethodHopInventory     = "hop_inventory"        // rank 3 — hop address → known interface/resource
	MethodAppBinding       = "app_endpoint_binding" // rank 4 — application declares its own endpoint
	MethodSessionStitch    = "flow_nat_stitch"      // rank 5 — flow/NAT session ties pre/post tuples
	MethodCloudRoute       = "cloud_route"          // rank 6 — INFERRED (supporting only)
	MethodTokenSimilarity  = "shared_token"         // rank 7 — CANDIDATE ONLY (never an edge)
	MethodUnresolved       = "unresolved"
)

// Evidence classes (§4).
const (
	ClassObserved  = "observed"
	ClassInferred  = "inferred"
	ClassCandidate = "candidate"
	ClassNone      = "none"
)

// rankOf maps a method to its §3 rank (0 = unresolved).
func rankOf(method string) int {
	switch method {
	case MethodResourceIdentity:
		return 1
	case MethodEndpointBinding:
		return 2
	case MethodHopInventory:
		return 3
	case MethodAppBinding:
		return 4
	case MethodSessionStitch:
		return 5
	case MethodCloudRoute:
		return 6
	case MethodTokenSimilarity:
		return 7
	}
	return 0
}

// Authoritative reports whether a method may create an authoritative graph edge.
// Ranks 1–5 only (§3). This is the single gate every caller must go through.
func Authoritative(method string) bool {
	r := rankOf(method)
	return r >= 1 && r <= 5
}

// ── validity windows (§6 rule 2) ─────────────────────────────────────────────

// Window is a binding's validity window. ValidTo == nil means "currently valid".
type Window struct {
	From time.Time  `json:"valid_from"`
	To   *time.Time `json:"valid_to,omitempty"`
}

// Contains reports whether t falls inside the window. A zero From is treated as
// "since forever" (an inventory row with no first-seen is still usable), but an
// EXPIRED binding (To before t) never resolves — bindings MOVE, and a resolution
// against a window that has closed is exactly the stale-join bug this contract
// exists to prevent.
func (w Window) Contains(t time.Time) bool {
	if !w.From.IsZero() && t.Before(w.From) {
		return false
	}
	if w.To != nil && t.After(*w.To) {
		return false
	}
	return true
}

// ── facts (the resolver's inputs; every one is tenant-stamped) ───────────────

// ResourceIdentity — RANK 1. The measurement itself names an immutable resource
// id (an in-guest agent reporting its instance id, a cloud transaction naming the
// resource that served it). Same resource_id ⇒ same thing, no inference at all.
type ResourceIdentity struct {
	TenantID       string
	ResourceID     string
	NetworkContext string
	Kind           string
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// NICBinding — RANK 2. A tenant-scoped endpoint→interface/resource binding, valid
// during the observation: the cloud NIC/ENI inventory (AWS ENI private_ips, Azure
// NIC), agent registration, orchestration inventory, deployment metadata.
//
// This is what binds 10.60.10.10 → the AWS application host: the ENI inventory
// says which resource OWNS that private IP. Not a token. Not a name.
type NICBinding struct {
	TenantID       string
	Address        string
	NetworkContext string
	ResourceID     string
	InterfaceID    string // eni-… / nic id
	Kind           string // app_endpoint | nva | cloud_edge | …
	Service        string // app attributed to the resource, when the inventory knows it
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// InterfaceBinding — RANK 3. Path-hop inventory resolution: the hop address
// resolves to a known interface/resource in THIS tenant + network context, within
// the validity window (the device/interface registry from SNMP/gNMI discovery).
type InterfaceBinding struct {
	TenantID       string
	Address        string
	NetworkContext string
	DeviceID       string
	InterfaceID    string
	Kind           string // lan_gateway | wan_edge | transit | …
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// AppBinding — RANK 4. The application declares its own listen endpoint (app agent
// registration, orchestration/deployment metadata, application telemetry that names
// its service + host). The app↔endpoint edge in the acceptance case comes from
// HERE (or rank 2) — provably not from a shared token.
type AppBinding struct {
	TenantID       string
	Service        string
	Address        string
	NetworkContext string
	ResourceRef    string
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// SessionStitch — RANK 5. A session record ties pre- and post-translation tuples
// (a NAT/flow session). MODELLED here and honoured by the resolver; the platform
// has no session-record source wired yet, so in production this slice is normally
// empty (see PathFacts.SessionSourceAvailable). We do not fake one.
type SessionStitch struct {
	TenantID       string
	PreAddress     string
	PostAddress    string
	NetworkContext string
	ResourceRef    string
	Transformation string // nat | proxy | load_balancer
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// RouteRelation — RANK 6, INFERRED. A cloud route-table / Azure-UDR relation
// (AWS route tables, Azure UDRs, BGP, SD-WAN policy): "the app subnet's default
// route points at the NVA's ENI". It EXPLAINS an observed hop and may PREDICT an
// edge, but it may never assert that traffic took it (§4).
type RouteRelation struct {
	TenantID       string
	NetworkContext string
	FromSubnet     string
	FromSubnetName string
	Destination    string // prefix
	ToRef          string // resource id or address of the next hop
	ToKind         string // internet_gateway | nat_gateway | nva | vpc_endpoint | vpn_gateway
	RouteTable     string
	Window         Window
	EvidenceRef    string
	DataClass      string
	ObservedAt     time.Time
}

// NameToken — RANK 7, CANDIDATE ONLY. Shared tokens, reverse DNS, name similarity.
// Never an authoritative edge. Ever.
type NameToken struct {
	TenantID       string
	Token          string // a shared token, an rDNS name, a hostname
	Ref            string // what the token names
	NetworkContext string
	EvidenceRef    string
	DataClass      string
}

// PathFacts is the tenant-scoped fact base the resolver consults. The caller
// assembles it from the real inventories; the resolver never reaches out.
type PathFacts struct {
	ResourceIdentities []ResourceIdentity
	NICBindings        []NICBinding
	InterfaceBindings  []InterfaceBinding
	AppBindings        []AppBinding
	Sessions           []SessionStitch
	Routes             []RouteRelation
	Tokens             []NameToken
	// SessionSourceAvailable states honestly whether a flow/NAT session source is
	// wired at all. false ⇒ rank 5 is UNAVAILABLE (not "no match"), which the API
	// surfaces as an evidence gap instead of silently pretending the path has no
	// NAT.
	SessionSourceAvailable bool
}

// ── query & result ───────────────────────────────────────────────────────────

// Query is one resolution request: an address (or a declared resource id) at a
// point in time, inside a tenant + network context.
type Query struct {
	TenantID           string
	Address            string
	NetworkContext     string
	DeclaredResourceID string // set when the measurement itself named a resource (rank 1)
	At                 time.Time
	Tokens             []string // rank-7 material ONLY (shared tokens)
	Hostname           string   // rank-7 material ONLY (rDNS)
	// IncludeNonLive admits non-live facts (synthetic/replay/lab). Default false:
	// customer resolution runs on live evidence only (§1).
	IncludeNonLive bool
}

// SupportingRel is an INFERRED (rank 6) relation attached to a resolution. It is
// rendered as a supporting edge and may explain an observed hop; it can never
// stand in for one.
type SupportingRel struct {
	Method      string `json:"method"`
	Class       string `json:"class"` // always "inferred"
	Ref         string `json:"ref"`   // the related resource/next-hop
	ToKind      string `json:"to_kind,omitempty"`
	Destination string `json:"destination,omitempty"`
	RouteTable  string `json:"route_table,omitempty"`
	EvidenceRef string `json:"evidence_ref"`
	DataClass   string `json:"data_class"`
	Confidence  string `json:"confidence"`
}

// Resolution is the resolver's verdict for one address.
type Resolution struct {
	// EntityRef is the AUTHORITATIVE binding — device_id | cloud_resource_id |
	// interface_id. Written by ranks 1–5 ONLY.
	EntityRef string `json:"entity_ref,omitempty"`
	// CandidateRef is a rank-7 lead (token/rDNS/name). NOTHING in the graph reads
	// it. It exists so an operator can see the coincidence and judge it — which is
	// what a coincidence detector is actually good for.
	CandidateRef   string          `json:"candidate_ref,omitempty"`
	Method         string          `json:"method"`
	Rank           int             `json:"rank"`
	Class          string          `json:"class"`
	Confidence     string          `json:"confidence"`
	Authoritative  bool            `json:"authoritative"`
	Kind           string          `json:"kind,omitempty"`
	Service        string          `json:"service,omitempty"`
	Transformation string          `json:"transformation,omitempty"`
	EvidenceRef    string          `json:"evidence_ref,omitempty"`
	ObservedAt     time.Time       `json:"observed_at,omitempty"`
	DataClass      string          `json:"data_class,omitempty"`
	Supporting     []SupportingRel `json:"supporting,omitempty"`
}

// Unresolved is the honest default: unknown stays unknown (§8). It is what the
// resolver returns when no rank 1–5 fact matches — never a guess.
func Unresolved() Resolution {
	return Resolution{Method: MethodUnresolved, Rank: 0, Class: ClassNone, Confidence: ConfUnknown}
}

// ── the resolver ─────────────────────────────────────────────────────────────

// admissible applies the §6 join rules that are common to every fact:
//  1. same immutable tenant_id (exact; never inferred from an address),
//  2. compatible network context (exact; a transition must be modelled, not assumed),
//  3. compatible time ranges (the binding must be valid AT the observation),
//  4. data class (live-only unless the caller explicitly opted in).
func admissible(q Query, tenant, netCtx, dataClass string, w Window) bool {
	if normalize(tenant) != normalize(q.TenantID) {
		return false // §6.1 — the hard wall. No cross-tenant join, ever.
	}
	if normalize(netCtx) != normalize(q.NetworkContext) {
		return false // §6.4 — an address is meaningless without its context.
	}
	if !w.Contains(q.At) {
		return false // §6.2 — bindings MOVE; a closed window does not resolve.
	}
	if !q.IncludeNonLive && dataClass != DataClassLive {
		return false // §1 — non-live evidence never enters a customer resolution.
	}
	return true
}

// Resolve applies the §3 ranking and returns the FIRST (highest-rank) match.
// Ranks are tried strictly in order, so a rank-2 ENI binding always beats a
// rank-3 interface guess, and no rank-6/7 material can ever outrank an
// observation.
//
// Rank 6 is collected as Supporting on whatever the outcome is (it explains an
// observed hop, or offers the only — non-authoritative — account of an
// unresolved one). Rank 7 fills CandidateRef only when NOTHING observed matched,
// and even then leaves EntityRef empty.
func (f PathFacts) Resolve(q Query) Resolution {
	res := Unresolved()

	// rank 1 — immutable resource identity.
	if id := strings.TrimSpace(q.DeclaredResourceID); id != "" {
		for _, ri := range f.ResourceIdentities {
			if !admissible(q, ri.TenantID, ri.NetworkContext, ri.DataClass, ri.Window) {
				continue
			}
			if normalize(ri.ResourceID) != normalize(id) {
				continue
			}
			res = Resolution{
				EntityRef: ri.ResourceID, Method: MethodResourceIdentity, Rank: 1,
				Class: ClassObserved, Confidence: ConfAuthoritative, Authoritative: true,
				Kind: ri.Kind, EvidenceRef: ri.EvidenceRef, ObservedAt: ri.ObservedAt, DataClass: ri.DataClass,
			}
			return f.withSupporting(q, res)
		}
	}

	// rank 2 — tenant-scoped endpoint→interface/resource binding (cloud NIC/ENI
	// inventory, agent registration, orchestration inventory).
	for _, nb := range f.NICBindings {
		if !admissible(q, nb.TenantID, nb.NetworkContext, nb.DataClass, nb.Window) {
			continue
		}
		if !sameAddr(nb.Address, q.Address) {
			continue
		}
		ref := nb.ResourceID
		if ref == "" {
			ref = nb.InterfaceID
		}
		res = Resolution{
			EntityRef: ref, Method: MethodEndpointBinding, Rank: 2,
			Class: ClassObserved, Confidence: ConfAuthoritative, Authoritative: true,
			Kind: nb.Kind, Service: nb.Service, EvidenceRef: nb.EvidenceRef,
			ObservedAt: nb.ObservedAt, DataClass: nb.DataClass,
		}
		return f.withSupporting(q, res)
	}

	// rank 3 — path-hop inventory resolution (the hop address is a known interface
	// in this tenant + context, within the window).
	for _, ib := range f.InterfaceBindings {
		if !admissible(q, ib.TenantID, ib.NetworkContext, ib.DataClass, ib.Window) {
			continue
		}
		if !sameAddr(ib.Address, q.Address) {
			continue
		}
		ref := ib.DeviceID
		if ref == "" {
			ref = ib.InterfaceID
		}
		res = Resolution{
			EntityRef: ref, Method: MethodHopInventory, Rank: 3,
			Class: ClassObserved, Confidence: ConfAuthoritative, Authoritative: true,
			Kind: ib.Kind, EvidenceRef: ib.EvidenceRef, ObservedAt: ib.ObservedAt, DataClass: ib.DataClass,
		}
		return f.withSupporting(q, res)
	}

	// rank 4 — application→endpoint binding (the app declares its own endpoint).
	for _, ab := range f.AppBindings {
		if !admissible(q, ab.TenantID, ab.NetworkContext, ab.DataClass, ab.Window) {
			continue
		}
		if !sameAddr(ab.Address, q.Address) {
			continue
		}
		ref := ab.ResourceRef
		if ref == "" {
			ref = ab.Service
		}
		res = Resolution{
			EntityRef: ref, Method: MethodAppBinding, Rank: 4,
			Class: ClassObserved, Confidence: ConfStrong, Authoritative: true,
			Kind: KindAppEndpoint, Service: ab.Service, EvidenceRef: ab.EvidenceRef,
			ObservedAt: ab.ObservedAt, DataClass: ab.DataClass,
		}
		return f.withSupporting(q, res)
	}

	// rank 5 — flow / NAT-session stitching (a session record ties the pre- and
	// post-translation tuples; the transformation is EXPLICIT, never inferred from
	// address coincidence).
	for _, ss := range f.Sessions {
		if !admissible(q, ss.TenantID, ss.NetworkContext, ss.DataClass, ss.Window) {
			continue
		}
		if !sameAddr(ss.PreAddress, q.Address) && !sameAddr(ss.PostAddress, q.Address) {
			continue
		}
		res = Resolution{
			EntityRef: ss.ResourceRef, Method: MethodSessionStitch, Rank: 5,
			Class: ClassObserved, Confidence: ConfStrong, Authoritative: true,
			Transformation: ss.Transformation, EvidenceRef: ss.EvidenceRef,
			ObservedAt: ss.ObservedAt, DataClass: ss.DataClass,
		}
		return f.withSupporting(q, res)
	}

	// Nothing observed. Rank 6 may still EXPLAIN the address (supporting), and
	// rank 7 may offer a candidate lead — but the endpoint stays UNRESOLVED:
	// entity_ref empty, confidence unknown, authoritative false.
	res = f.withSupporting(q, res)
	if c := f.candidate(q); c != "" {
		res.CandidateRef = c
		res.Method = MethodTokenSimilarity
		res.Rank = 7
		res.Class = ClassCandidate
		res.Confidence = ConfCandidate
		res.Authoritative = false
		res.EntityRef = "" // belt and braces: rank 7 NEVER names an entity.
	}
	return res
}

// withSupporting attaches the rank-6 INFERRED relations that bear on this address.
// They never change EntityRef, Method, Rank, Class or Authoritative — they are
// additive explanation (§4).
func (f PathFacts) withSupporting(q Query, res Resolution) Resolution {
	for _, rr := range f.Routes {
		if !admissible(q, rr.TenantID, rr.NetworkContext, rr.DataClass, rr.Window) {
			continue
		}
		// The relation bears on this address when it points AT it (the route's next
		// hop is this address/resource), which is what makes it an explanation of
		// the observed hop.
		if !sameAddr(rr.ToRef, q.Address) && normalize(rr.ToRef) != normalize(res.EntityRef) {
			continue
		}
		res.Supporting = append(res.Supporting, SupportingRel{
			Method: MethodCloudRoute, Class: ClassInferred, Ref: rr.ToRef, ToKind: rr.ToKind,
			Destination: rr.Destination, RouteTable: rr.RouteTable, EvidenceRef: rr.EvidenceRef,
			DataClass: rr.DataClass, Confidence: ConfStrong,
		})
	}
	sort.SliceStable(res.Supporting, func(i, j int) bool {
		return res.Supporting[i].Destination < res.Supporting[j].Destination
	})
	return res
}

// ServiceOf returns the APPLICATION exposed at an endpoint — the service tail of
// the spine (§10's "AWS application"). It is admissible from exactly two places:
//
//	rank 4 — the application declares its own listen endpoint (app telemetry /
//	         agent registration / deployment metadata), and
//	rank 2 — the cloud inventory attributes the resource that OWNS the address.
//
// Rank 4 is preferred because the app naming itself is the more direct statement.
// Nothing else can produce a service tail — in particular no token/name overlap
// between the application and a seam endpoint (§10 acceptance).
func (f PathFacts) ServiceOf(q Query) *ServiceTail {
	for _, ab := range f.AppBindings {
		if !admissible(q, ab.TenantID, ab.NetworkContext, ab.DataClass, ab.Window) {
			continue
		}
		if !sameAddr(ab.Address, q.Address) || ab.Service == "" {
			continue
		}
		ref := ab.ResourceRef
		if ref == "" {
			ref = ab.Service
		}
		return &ServiceTail{
			Service: ab.Service, EntityRef: ref, Method: MethodAppBinding, Confidence: ConfStrong,
			EvidenceRef: ab.EvidenceRef, ObservedAt: ab.ObservedAt, DataClass: ab.DataClass,
		}
	}
	for _, nb := range f.NICBindings {
		if !admissible(q, nb.TenantID, nb.NetworkContext, nb.DataClass, nb.Window) {
			continue
		}
		if !sameAddr(nb.Address, q.Address) || nb.Service == "" {
			continue
		}
		return &ServiceTail{
			Service: nb.Service, EntityRef: nb.ResourceID, Method: MethodEndpointBinding,
			Confidence: ConfAuthoritative, EvidenceRef: nb.EvidenceRef, ObservedAt: nb.ObservedAt,
			DataClass: nb.DataClass,
		}
	}
	return nil
}

// candidate returns a rank-7 match (shared token / rDNS / name). It is a LEAD,
// not a resolution: the caller may show it, and may never build an edge from it.
func (f PathFacts) candidate(q Query) string {
	want := map[string]bool{}
	for _, t := range q.Tokens {
		if t = normalize(t); t != "" {
			want[t] = true
		}
	}
	if h := normalize(q.Hostname); h != "" {
		want[h] = true
	}
	if len(want) == 0 {
		return ""
	}
	for _, nt := range f.Tokens {
		// Even a candidate must not cross a tenant: a name coincidence between two
		// tenants is not even a lead, it is noise (§9).
		if normalize(nt.TenantID) != normalize(q.TenantID) {
			continue
		}
		if want[normalize(nt.Token)] {
			return nt.Ref
		}
	}
	return ""
}

// sameAddr compares two addresses for identity. Case/space-insensitive; no CIDR
// containment, no prefix matching — an address either IS the binding's address or
// it is not.
func sameAddr(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return normalize(a) == normalize(b)
}
