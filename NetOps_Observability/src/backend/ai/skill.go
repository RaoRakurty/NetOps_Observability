// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill.go — the SKILLS LAYER (IRIS Phase A): troubleshooting method as DATA,
// not as Go control flow.
//
// Each skill is one `skills/<name>/SKILL.md` file compiled into the binary by
// the embed directive below. A skill states, in frontmatter, WHEN it applies,
// WHICH of our governed read-only tools to gather with, WHAT to look for, and
// WHERE to go next; the prose body below the frontmatter is the method itself,
// handed to the model as reference material.
//
// Why data and not code:
//   - the method is reviewable by a network engineer without reading Go;
//   - the tool plan is DETERMINISTIC and inspectable before a model ever runs;
//   - a decision that points at a skill or a tool which does not exist fails the
//     loader (and therefore CI), so the method cannot drift away from the
//     platform's actual capabilities.
//
// Security stance (CLAUDE.md §15). A skill loaded here is server-owned content:
// it is compiled in, and nothing in a skill can widen what the caller may run.
// Every gather step is re-gated at execution by the Policy Engine and the
// caller's Principal, and every tool it may name is read-only by construction
// (§4/LLM07 least privilege, LLM08 no excessive agency).
//
// A customer's runbook (skill_source.go, tracker 337 N-F2) passes the SAME parser
// and the SAME closed vocabularies, but carries Origin tenant: its text is DATA
// and never reaches a system-prompt position (skill_run.go, LLM01).
//
// FORMAT (a deliberately tiny, strict dialect — not general YAML, so there is no
// parser surface to be surprised by):
//
//	---
//	name: bgp-session-down          # must equal the directory name
//	layer: bgp                      # one of the SkillLayer constants
//	version: 1                      # integer >= 1
//	when_to_use: bgp down, peer idle # comma-separated match phrases
//	symptom_kinds: bgp, routing      # comma-separated symptom classes
//	tools: get_rca_verdict, search_logs   # this skill's tool allowlist
//	gather:
//	  - get_rca_verdict(correlation_id)
//	  - search_logs(device, query=BGP, window=6h)
//	look_for:
//	  - one observation per bullet
//	decisions:
//	  - next=interface-down when the link beneath it is down
//	  - next=log-confirmation when signature=none the capture matched nothing
//	  - verdict=what a conclusion must state
//	  - escalate=who to hand it to
//	---
//	prose body …
//
// A `next=` line may carry a MACHINE CONDITION (IRIS Phase A2): when the first
// word after `when ` contains an `=`, it must be a `key=value` condition from
// the closed vocabulary in skillConditionKeys — anything else is a load error,
// so a typo can never degrade into a rule that silently never fires. The rest of
// the line is the human reason. A `when` clause WITHOUT an `=` in its first word
// stays a human-only reason: it is shown to the operator and offered to the
// model as a closed choice, but it never fires a deterministic hop.
//
// In a gather step, a BARE identifier binds that tool argument from the
// server-resolved entity of the same name (never from the model); `k=v` is a
// literal the skill author chose. A step whose bound entity is unavailable is
// skipped honestly rather than guessed at.

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed skills/*/SKILL.md
var skillsFS embed.FS

// SkillLayer is the OSI-ish layer a skill owns. The eight domain layers are the
// bisection order; `method` is reserved for the single top-level entry skill
// (osi-bisection), which selects among the others rather than owning a layer.
type SkillLayer string

const (
	LayerMethod      SkillLayer = "method"
	LayerPhysical    SkillLayer = "physical"
	LayerPlatform    SkillLayer = "platform" // device health: CPU, memory, environment, clock
	LayerL2          SkillLayer = "l2"
	LayerIGP         SkillLayer = "igp"
	LayerBGP         SkillLayer = "bgp"
	LayerWANOverlay  SkillLayer = "wan_overlay" // SD-WAN / VPN overlay over the transports
	LayerPathSeam    SkillLayer = "path_seam"
	LayerServices    SkillLayer = "services" // network services the path depends on: DNS, NTP, DHCP
	LayerApplication SkillLayer = "application"
	LayerSecurity    SkillLayer = "security"
	LayerLogs        SkillLayer = "logs"
)

// skillLayerOrder is the bisection order the method skill follows. Index 0 is
// the entry method; the rest are checked bottom-up.
var skillLayerOrder = []SkillLayer{
	LayerMethod, LayerPhysical, LayerPlatform, LayerL2, LayerIGP, LayerBGP,
	LayerWANOverlay, LayerPathSeam, LayerServices, LayerApplication, LayerSecurity, LayerLogs,
}

func validSkillLayer(l SkillLayer) bool {
	for _, v := range skillLayerOrder {
		if v == l {
			return true
		}
	}
	return false
}

// LayerRank is the bisection position of a layer (lower = checked earlier).
// Unknown layers sort last so they can never pre-empt a real layer.
func LayerRank(l SkillLayer) int {
	for i, v := range skillLayerOrder {
		if v == l {
			return i
		}
	}
	return len(skillLayerOrder)
}

// skillEntities is the closed set of entity names a gather step may bind from.
// The server resolves each of these deterministically (UI context + the
// caller's tenant-scoped inventory) BEFORE any tool runs — the model never
// supplies one, which is what keeps a skill from becoming an injection vector.
var skillEntities = map[string]bool{
	"correlation_id": true, // the RCA case in scope
	"device_id":      true, // canonical inventory id of the resolved device
	"device":         true, // operator-facing name of the resolved device
	"seam":           true, // seam id/type in scope
	"peer":           true, // peer/neighbour address in scope (IRIS Phase B)
	"prefix":         true, // prefix in scope (IRIS Phase B)
}

// liveStateTools are the gather steps that read what is TRUE NOW on a device.
// They are the reason `recall_investigations` may never lead a gather: NetClaw's
// rule — "never guess device state, run a show command first; never carry
// assumptions between sessions" — is enforced structurally by the loader, not
// left to the prose of each skill.
var liveStateTools = map[string]bool{
	"get_device_state":        true,
	"run_protocol_diagnostic": true,
}

// memoryToolName is the one tool that returns PRIOR conclusions rather than
// present facts.
const memoryToolName = "recall_investigations"

// validateMemoryOrder enforces the Phase-B gather ordering: investigation
// memory is gathered only AFTER live state, and never first. A skill that
// consulted memory before reading the device would be doing exactly what the
// design forbids — carrying a past conclusion into a present diagnosis.
func validateMemoryOrder(gather []GatherStep) error {
	memAt := -1
	for i, g := range gather {
		if g.Tool == memoryToolName && memAt < 0 {
			memAt = i
		}
	}
	if memAt < 0 {
		return nil
	}
	if memAt == 0 {
		return fmt.Errorf("gather step 1 is %s: investigation memory is PRIOR CONTEXT and may never be the first evidence gathered", memoryToolName)
	}
	for i, g := range gather {
		if liveStateTools[g.Tool] && i > memAt {
			return fmt.Errorf("gather step %d (%s) reads LIVE state after %s: memory may only be gathered AFTER live state, never before",
				i+1, g.Tool, memoryToolName)
		}
	}
	return nil
}

// skillToolAllowlist is the closed set of tool names a skill may name. Every
// entry is READ-ONLY (CapRead) and governed by the Policy Engine at execution.
// A skill naming anything else fails the loader — this is the structural half of
// "the model can never request a device write" (the Policy Engine is the other).
var skillToolAllowlist = map[string]bool{
	// Phase-B addition: prior CONCLUDED investigations for the entity in scope.
	// Read-only and signal-free — memory is evidence, never a routing rule.
	"recall_investigations": true,
	// Design item 10: configuration change history. Metadata-only reads (and a
	// redacted diff) over the caller's own config-backup register — the "was
	// there a change at the same time?" question every adjacency skill asks.
	"get_recent_changes": true,
	"get_config_diff":    true,
	// Phase-A4 additions: the show-first state battery and the read-only BGP
	// operations reads.
	"get_device_state":    true,
	"get_bgp_watchlist":   true,
	"get_bgp_rpki":        true,
	"get_bgp_feed_recent": true,
	// Phase-A additions.
	"run_protocol_diagnostic": true,
	"get_security_findings":   true,
	"get_topology_context":    true,
	"get_case_timeline":       true,
	"get_rca_verdict":         true,
	// Pre-existing governed reads a skill may lean on.
	"get_device_health":          true,
	"search_logs":                true,
	"get_metric_anomalies":       true,
	"get_problem_evidence":       true,
	"get_active_major_incidents": true,
	// NetClaw ingestion Batch 0 (2026-11-13): governed reads that already carry a
	// tool contract, so a method can ground on the whole network (design
	// reading), on traffic (congestion), and on the engine's own scope (who is
	// and who is NOT affected).
	"get_network_topology":  true,
	"get_top_talkers":       true,
	"get_flow_summary":      true,
	"get_blast_radius":      true,
	"get_affected_entities": true,
}

// SkillOrigin says who wrote a skill, which decides where its text may go.
type SkillOrigin string

const (
	// SkillOriginCompiled is embedded in the binary and reviewed with the code.
	// Its text is a system instruction. LoadSkills is the only thing that stamps
	// it, so a skill built any other way is treated as customer text (see
	// customerAuthored): the unsafe mistake is not available by omission.
	SkillOriginCompiled SkillOrigin = "compiled"
	// SkillOriginTenant is a customer's. Its text is DATA, in the user message.
	SkillOriginTenant SkillOrigin = "tenant"
)

// SkillKind says what a skill is FOR. It is a kind and not an "executable" flag
// because the safe reading has to be the one a reader reaches first.
type SkillKind string

const (
	// SkillKindInvestigative is a method Iris runs: it gathers and it hands off.
	SkillKindInvestigative SkillKind = "investigative"
	// SkillKindMOP is a procedure a human follows. Nothing executes one: it never
	// enters an overlay, is never a next= target and is never selected.
	SkillKindMOP SkillKind = "mop"
)

// maxMOPSteps bounds a MOP's steps: block.
const maxMOPSteps = 30

// GatherStep is one planned tool call: which tool, which arguments bind from
// resolved entities, and which are literals the skill author fixed.
type GatherStep struct {
	Tool string
	// Bind maps a TOOL ARGUMENT NAME to the entity name it binds from. A bare
	// identifier binds the entity of the same name; `arg=@entity` binds a
	// differently named one (see Strict).
	Bind map[string]string
	// Args are literal argument values chosen by the skill author.
	Args map[string]string
	// Strict names the bound arguments authored as `arg=@entity`: the author
	// bound a DIFFERENT entity on purpose (target=@prefix), so the step is only
	// meaningful with it and is skipped — honestly — when it does not resolve,
	// instead of running at a wider scope the author never asked for.
	Strict map[string]bool
}

// BindOrder is the deterministic (sorted) list of bound argument names, so a
// step renders and audits identically on every run.
func (g GatherStep) BindOrder() []string {
	out := make([]string, 0, len(g.Bind))
	for k := range g.Bind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SkillDecisionKind is what a decision line does.
type SkillDecisionKind string

const (
	DecisionNext     SkillDecisionKind = "next"     // hand off to another skill
	DecisionVerdict  SkillDecisionKind = "verdict"  // what a conclusion must state
	DecisionEscalate SkillDecisionKind = "escalate" // who owns it beyond us
)

// ---- machine conditions (IRIS Phase A2) ------------------------------------
//
// A condition is `key=value` over a CLOSED vocabulary of facts the server itself
// derives from the evidence gathered so far (skill_chain.go). The model never
// supplies a fact and never supplies a key: a condition can only ever select a
// skill the author already declared, so the worst a manipulated device string
// could do is pick an authored branch — never a new tool, a new skill, or a
// wider scope.

const (
	// CondSignature fires on a protocol-diagnostic signature id, or on the
	// reserved value CondSignatureNone ("a diagnostic ran and nothing matched").
	CondSignature = "signature"
	// CondEvidenceKind fires when an evidence item of that kind was gathered.
	CondEvidenceKind = "evidence:kind"
	// CondVerdictTier fires on the RCA engine's verdict tier.
	CondVerdictTier = "verdict:tier"
	// CondVerdictPhrase fires when the engine's own operator phrase/title
	// contains that word — the engine's words, never the model's.
	CondVerdictPhrase = "verdict:phrase"
	// CondNote fires when a server-authored collection note contains that token.
	CondNote = "note"
	// CondToolPrefix + a tool name fires on that tool's outcome this turn.
	CondToolPrefix = "tool:"
	// CondStatePrefix + a FACET fires on a TYPED device-state field the
	// show-first state battery actually read (`state:if_oper=down`). The value
	// set is enumerated per facet in skillStateFacets, and every fact is derived
	// from a showparse typed row by the server — never from raw device text and
	// never from the model. A `state:` rule may only be authored by a skill that
	// declares get_device_state, so a rule can never depend on state the skill
	// does not gather.
	CondStatePrefix = "state:"
	// CondTopoPrefix + a FACET fires on a design fact get_network_topology
	// declared about the caller's whole network (`topo:spof=present`): the
	// overlay's shape, whether the discovered adjacencies hold a single point
	// of failure, and whether the reading's coverage is full or partial. Like
	// state:, a topo: rule may only be authored by a skill that declares the
	// tool, so it can never depend on a read the skill does not make.
	CondTopoPrefix = "topo:"
	// CondSignatureNone is the reserved CondSignature value: a protocol
	// diagnostic RAN this turn, CAPTURED OUTPUT, and no known signature matched
	// it. "Captured output" is load-bearing — see CondSignatureUncollected.
	CondSignatureNone = "none"
	// CondSignatureUncollected is the reserved CondSignature value for the
	// OTHER empty outcome: the diagnostic ran, every read-only command was
	// rejected by the device and NOTHING was captured. Before it existed both
	// outcomes collapsed into `signature=none`, so "7 of 7 commands failed, 0
	// bytes" was narrated as "we looked and no signature matched" — which an
	// operator reads as "we looked, it is fine" (QA 2026-09-03, D-4). The two
	// are now distinct facts and route differently.
	CondSignatureUncollected = "uncollected"
)

// skillToolOutcomes is the closed outcome vocabulary of a `tool:<name>=` condition.
// It is exactly the set skill_chain.go can derive from a gather step's fate.
var skillToolOutcomes = map[string]bool{
	"ok":        true, // the tool ran and returned
	"not_found": true, // ErrNotFound — unknown OR another tenant's id (§3a)
	"not_wired": true, // not registered / not implemented on this deployment
	"denied":    true, // the Policy Engine or the caller's permissions refused it
	"error":     true, // the tool failed
}

// skillEvidenceKinds is the closed evidence-kind vocabulary (EvidenceItem.Kind
// as produced by the registered tools and the DataSource).
var skillEvidenceKinds = map[string]bool{
	"app": true, "device": true, "doc": true, "finding": true, "flow": true,
	"integration": true, "knowledge": true, "log": true, "metric": true,
	"navigation": true, "ticket": true, "topology": true,
}

// skillVerdictTiers is the closed RCA verdict-tier vocabulary.
var skillVerdictTiers = map[string]bool{
	"confirmed": true, "suspected": true, "candidate": true, "undetermined": true,
}

// skillStateFacets is the closed `state:` vocabulary: FACET → its enumerated
// value set (IRIS Phase A4). Each facet is a question the state battery can
// answer from a TYPED showparse field, and each value is a conclusion the
// server derives deterministically:
//
//	collect    how the live read itself went (an unread device is not a clean one)
//	if_oper    the subject interface's operational/line-protocol state
//	if_errors  whether any error/CRC/drop counter on the read interfaces is non-zero
//	igp_nbr    the WORST OSPF/IS-IS adjacency state on the device
//	bgp_peer   the WORST BGP neighbour FSM state on the device
//	route      whether the looked-up prefix is in the routing table
//	l2_entry   whether the looked-up address is in the ARP / MAC table
//	platform   control-plane CPU / memory pressure (the design's ">90 %" flag)
//
// Adding a facet or a value is a DELIBERATE edit here plus a derivation in the
// server seam; nothing else can widen it, and the loader rejects anything else.
var skillStateFacets = map[string]map[string]bool{
	"collect": {
		"ok": true, "partial": true, "failed": true,
		"timed_out": true, "unsupported": true, "not_wired": true,
	},
	"if_oper":   {"up": true, "down": true, "admin_down": true},
	"if_errors": {"none": true, "present": true},
	"igp_nbr":   {"full": true, "not_full": true, "none": true},
	"bgp_peer": {
		"established": true, "idle": true, "active": true,
		"connect": true, "other": true, "none": true,
	},
	"route":    {"present": true, "absent": true},
	"l2_entry": {"present": true, "absent": true},
	"platform": {"ok": true, "cpu_high": true, "mem_high": true},
}

// skillTopoFacets is the closed `topo:` vocabulary: FACET → its value set. The
// values are exactly what get_network_topology declares (networkSignals).
var skillTopoFacets = map[string]map[string]bool{
	"overlay_shape": {"full_mesh": true, "hub_and_spoke": true, "partial_mesh": true, "unknown": true, "none": true},
	"spof":          {"present": true, "none": true, "unknown": true},
	"coverage":      {"full": true, "partial": true},
}

// validTopoFact reports whether facet=value is inside the closed topo: set.
func validTopoFact(facet, value string) bool {
	vals, ok := skillTopoFacets[facet]
	return ok && vals[value]
}

// topoConditionHuman renders a topo: condition as the reason a hop was taken.
func topoConditionHuman(facet, value string) string {
	switch facet {
	case "overlay_shape":
		switch value {
		case "none":
			return "the network has no SD-WAN overlay"
		case "unknown":
			return "the overlay's shape could not be read"
		}
		return "the overlay appears to be " + strings.ReplaceAll(value, "_", " ")
	case "spof":
		switch value {
		case "present":
			return "the discovered adjacencies hold a single point of failure"
		case "none":
			return "no single point of failure is in the discovered adjacencies"
		}
		return "single points of failure could not be computed"
	case "coverage":
		if value == "full" {
			return "the topology reading rests on adjacency and site evidence for every device"
		}
		return "the topology reading is partial — some evidence is not collected"
	}
	return CondTopoPrefix + facet + "=" + value
}

// StateFacets returns every `state:` facet name in sorted order (loader error
// messages, tests and documentation).
func StateFacets() []string {
	out := make([]string, 0, len(skillStateFacets))
	for k := range skillStateFacets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validStateFact reports whether facet=value is inside the closed `state:`
// vocabulary. It is the ONE gate: the loader calls it on an authored condition
// and the chain evaluator calls it again on a signal a tool declared.
func validStateFact(facet, value string) bool {
	vals, ok := skillStateFacets[facet]
	return ok && vals[value]
}

// stateConditionHuman renders a `state:` condition as the operator-facing
// reason a hop was taken.
func stateConditionHuman(facet, value string) string {
	switch facet {
	case "collect":
		switch value {
		case "ok":
			return "the device's live state was read in full"
		case "partial":
			return "only part of the device's live state could be read"
		case "not_wired":
			return "live device state could not be read on this deployment"
		case "unsupported":
			return "no read-only command is established for this platform"
		case "timed_out":
			return "the device did not answer the state read in time"
		default:
			return "the device's live state could not be read"
		}
	case "if_oper":
		switch value {
		case "admin_down":
			return "the interface is administratively down"
		case "down":
			return "the interface is operationally down"
		default:
			return "the interface is operationally up"
		}
	case "if_errors":
		if value == "present" {
			return "the interface is counting errors, CRCs or drops"
		}
		return "the interface reports no error counters"
	case "igp_nbr":
		switch value {
		case "full":
			return "every IGP adjacency read is fully established"
		case "none":
			return "the device has no IGP adjacency at all"
		default:
			return "an IGP adjacency is not fully established"
		}
	case "bgp_peer":
		switch value {
		case "established":
			return "the BGP session read is Established"
		case "none":
			return "the device has no BGP neighbour at all"
		case "other":
			return "the BGP session is in a non-Established state"
		default:
			return "the BGP session is " + value
		}
	case "route":
		if value == "present" {
			return "the prefix is in the routing table"
		}
		return "the device says the prefix is not in the routing table"
	case "l2_entry":
		if value == "present" {
			return "the address is in the ARP / MAC table"
		}
		return "the device says the address is not in the ARP / MAC table"
	case "platform":
		switch value {
		case "cpu_high":
			return "control-plane CPU is above 90%"
		case "mem_high":
			return "control-plane memory is above 90%"
		default:
			return "control-plane CPU and memory are within bounds"
		}
	default:
		return CondStatePrefix + facet + "=" + value
	}
}

var (
	reCondToken     = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)
	reCondSignature = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// SkillCondition is one machine-checkable guard on a next= decision.
type SkillCondition struct {
	Key   string // one of the Cond* keys, or CondToolPrefix + a declared tool
	Value string // validated against that key's closed vocabulary
}

// String renders the condition in its authored form (audit + docs).
func (c SkillCondition) String() string { return c.Key + "=" + c.Value }

// Human renders the condition as the operator-facing reason a hop was taken.
func (c SkillCondition) Human() string {
	switch {
	case c.Key == CondSignature && c.Value == CondSignatureNone:
		return "the protocol diagnostic ran and no known signature matched"
	case c.Key == CondSignature && c.Value == CondSignatureUncollected:
		return "the protocol diagnostic ran but the device rejected every read-only command, so nothing was captured"
	case c.Key == CondSignature:
		return "the " + c.Value + " signature fired"
	case c.Key == CondEvidenceKind:
		return c.Value + " evidence was gathered"
	case c.Key == CondVerdictTier:
		return "the RCA verdict is " + c.Value
	case c.Key == CondVerdictPhrase:
		return "the RCA verdict names \"" + c.Value + "\""
	case c.Key == CondNote:
		return "a collection note mentions \"" + c.Value + "\""
	case strings.HasPrefix(c.Key, CondStatePrefix):
		return stateConditionHuman(strings.TrimPrefix(c.Key, CondStatePrefix), c.Value)
	case strings.HasPrefix(c.Key, CondFactPrefix):
		return factHuman(c, factHolds, "", DeviceFacts{})
	case strings.HasPrefix(c.Key, CondTopoPrefix):
		return topoConditionHuman(strings.TrimPrefix(c.Key, CondTopoPrefix), c.Value)
	case strings.HasPrefix(c.Key, CondToolPrefix):
		tool := ToolLabel(strings.TrimPrefix(c.Key, CondToolPrefix))
		switch c.Value {
		case "ok":
			return tool + " returned data"
		case "not_found":
			return tool + " found nothing for the id in scope"
		case "not_wired":
			return tool + " is not available on this deployment"
		case "denied":
			return tool + " was not permitted for this caller"
		default:
			return tool + " failed"
		}
	default:
		return c.String()
	}
}

// parseSkillCondition validates one `key=value` machine condition against the
// closed vocabulary. `declared` is the skill's own tools: list — a tool:
// condition on a tool the skill never declared is a load error, so a rule can
// never depend on evidence the skill does not gather.
func parseSkillCondition(raw string, declared map[string]bool) (SkillCondition, error) {
	key, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	if !ok || key == "" || value == "" {
		return SkillCondition{}, fmt.Errorf("condition %q must be key=value", raw)
	}
	switch {
	case key == CondSignature:
		if value != CondSignatureNone && value != CondSignatureUncollected && !reCondSignature.MatchString(value) {
			return SkillCondition{}, fmt.Errorf("signature %q must be %q, %q or a signature id matching %s",
				value, CondSignatureNone, CondSignatureUncollected, reCondSignature)
		}
	case key == CondEvidenceKind:
		if !skillEvidenceKinds[value] {
			return SkillCondition{}, fmt.Errorf("evidence kind %q is not one of %v", value, sortedKeys(skillEvidenceKinds))
		}
	case key == CondVerdictTier:
		if !skillVerdictTiers[value] {
			return SkillCondition{}, fmt.Errorf("verdict tier %q is not one of %v", value, sortedKeys(skillVerdictTiers))
		}
	case key == CondVerdictPhrase, key == CondNote:
		if !reCondToken.MatchString(value) {
			return SkillCondition{}, fmt.Errorf("%s token %q must match %s", key, value, reCondToken)
		}
	case strings.HasPrefix(key, CondStatePrefix):
		facet := strings.TrimPrefix(key, CondStatePrefix)
		if _, known := skillStateFacets[facet]; !known {
			return SkillCondition{}, fmt.Errorf("state facet %q is not one of %v", facet, StateFacets())
		}
		if !validStateFact(facet, value) {
			return SkillCondition{}, fmt.Errorf("state value %q is not one of %v for facet %q",
				value, sortedKeys(skillStateFacets[facet]), facet)
		}
		// A state rule may only be authored by a skill that actually reads state
		// — otherwise the condition could only ever fire on another skill's
		// evidence, which is exactly the silent-never-fires trap this loader
		// exists to prevent.
		if !declared["get_device_state"] {
			return SkillCondition{}, fmt.Errorf("a %s condition needs get_device_state in this skill's tools: list", CondStatePrefix)
		}
	case strings.HasPrefix(key, CondFactPrefix):
		// A discovered-device fact (skill_facts.go). Resolved once per turn by
		// the server for the device in scope; no tool needs to be declared.
		return parseFactCondition(key, value)
	case strings.HasPrefix(key, CondTopoPrefix):
		facet := strings.TrimPrefix(key, CondTopoPrefix)
		if _, known := skillTopoFacets[facet]; !known {
			return SkillCondition{}, fmt.Errorf("topo facet %q is not one of %v", facet, sortedKeysOfMaps(skillTopoFacets))
		}
		if !validTopoFact(facet, value) {
			return SkillCondition{}, fmt.Errorf("topo value %q is not one of %v for facet %q", value, sortedKeys(skillTopoFacets[facet]), facet)
		}
		if !declared["get_network_topology"] {
			return SkillCondition{}, fmt.Errorf("a %s condition needs get_network_topology in this skill's tools: list", CondTopoPrefix)
		}
	case strings.HasPrefix(key, CondToolPrefix):
		tool := strings.TrimPrefix(key, CondToolPrefix)
		if !skillToolAllowlist[tool] {
			return SkillCondition{}, fmt.Errorf("condition tool %q is not on the skill tool allowlist", tool)
		}
		if !declared[tool] {
			return SkillCondition{}, fmt.Errorf("condition tool %q is not in this skill's tools: list", tool)
		}
		if !skillToolOutcomes[value] {
			return SkillCondition{}, fmt.Errorf("tool outcome %q is not one of %v", value, sortedKeys(skillToolOutcomes))
		}
	default:
		return SkillCondition{}, fmt.Errorf("condition key %q is not one of %s, %s, %s, %s, %s, %s<facet>, %s<key>, %s<tool>",
			key, CondSignature, CondEvidenceKind, CondVerdictTier, CondVerdictPhrase, CondNote,
			CondStatePrefix, CondFactPrefix, CondToolPrefix)
	}
	return SkillCondition{Key: key, Value: value}, nil
}

// SkillDecision is one authored decision. Target is the next skill's name for
// DecisionNext and empty otherwise. Cond, when non-nil, is the machine condition
// that makes the hop DETERMINISTIC; a nil Cond is a human-only reason.
type SkillDecision struct {
	Kind   SkillDecisionKind
	Target string
	Reason string
	Cond   *SkillCondition
}

// Skill is one parsed, validated troubleshooting method.
type Skill struct {
	Name         string
	Layer        SkillLayer
	Version      int
	WhenToUse    []string // lowercased match phrases
	SymptomKinds []string // lowercased symptom classes
	Tools        []string // this skill's tool allowlist (subset of skillToolAllowlist)
	// AppliesWhen are the DISCOVERED-device conditions under which this method
	// applies (`applies_when: fact:adjacency=ospf`). Every one must hold or be
	// unknown; one established false and the method is not run (skill_facts.go).
	AppliesWhen []SkillCondition
	Gather      []GatherStep
	LookFor     []string
	Decisions   []SkillDecision
	Body        string
	// Cases are the skill's authored BEHAVIOURAL cases (skill_cases.go), loaded
	// from `skills/<name>/CASES.yaml` by the same loader on the same terms: a
	// method that ships with none does not load at all.
	Cases []SkillCase
	// Origin says who wrote this skill. Stamped by the loader that produced it,
	// never by anything in the source text.
	Origin SkillOrigin
	// TenantID owns a tenant-origin skill. It is stamped by the caller from the
	// authenticated principal (§3a rule 2) and has no frontmatter key.
	TenantID string
	// Kind is investigative unless the source says `kind: mop`.
	Kind SkillKind
	// Steps are a MOP's ordered steps, for a human. Never dispatched.
	Steps []string
}

// customerAuthored reports whether this skill's text is DATA. Only the compiled
// stamp makes it an instruction, so a skill nobody stamped fails closed.
func (s *Skill) customerAuthored() bool { return s.Origin != SkillOriginCompiled }

// isMOP reports whether this skill is a procedure for a human.
func (s *Skill) isMOP() bool { return s.Kind == SkillKindMOP }

// hopAllowed is the one-directional reach rule, applied at Overlay time and again
// by the running chain: a customer's runbook may hand off to Correlix's methods
// or to its own tenant's runbooks; a compiled method can never reach a customer's
// text; and a MOP is nobody's next step.
func hopAllowed(from, to *Skill) bool {
	if to.isMOP() {
		return false
	}
	if !to.customerAuthored() {
		return true
	}
	return from.customerAuthored() && from.TenantID == to.TenantID
}

// Ref is the provenance stamp returned with an answer so the UI can show which
// method produced it.
func (s *Skill) Ref() SkillRef {
	ref := SkillRef{Name: s.Name, Layer: string(s.Layer), Version: s.Version}
	if s.customerAuthored() {
		ref.Origin = string(SkillOriginTenant)
	}
	return ref
}

// NextSkills lists the skills this one hands off to, in authored order.
func (s *Skill) NextSkills() []string {
	var out []string
	for _, d := range s.Decisions {
		if d.Kind == DecisionNext && d.Target != "" {
			out = append(out, d.Target)
		}
	}
	return out
}

// SkillRef is the answer-level provenance stamp (name + layer + version). Origin
// is set only on a customer's runbook, so a UI can label it; a compiled method's
// JSON is byte-for-byte what it always was.
type SkillRef struct {
	Name    string `json:"name"`
	Layer   string `json:"layer"`
	Version int    `json:"version"`
	Origin  string `json:"origin,omitempty"`
}

// SkillSet is the loaded, validated skill catalog. Immutable after load.
type SkillSet struct {
	byName map[string]*Skill
	order  []string
}

// Names returns every skill name in sorted order.
func (s *SkillSet) Names() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.order))
	copy(out, s.order)
	return out
}

// Get returns a skill by name.
func (s *SkillSet) Get(name string) (*Skill, bool) {
	if s == nil {
		return nil, false
	}
	sk, ok := s.byName[name]
	return sk, ok
}

// Len reports how many skills loaded.
func (s *SkillSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.order)
}

var reSkillName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// LoadSkills parses and validates every embedded skill. Validation is STRICT and
// whole-set: an unknown layer, an undeclared tool, an unsatisfiable required
// argument, or a `next=` pointing at a skill that does not exist is an error,
// not a warning. A silently-skipped skill would make the assistant claim a
// method it cannot actually run.
func LoadSkills() (*SkillSet, error) {
	entries, err := fs.Glob(skillsFS, "skills/*/SKILL.md")
	if err != nil {
		return nil, fmt.Errorf("skills: glob: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("skills: no SKILL.md files are embedded")
	}
	sort.Strings(entries)
	set := &SkillSet{byName: make(map[string]*Skill, len(entries))}
	for _, p := range entries {
		raw, rerr := skillsFS.ReadFile(p)
		if rerr != nil {
			return nil, fmt.Errorf("skills: read %s: %w", p, rerr)
		}
		dir := path.Base(path.Dir(p))
		sk, perr := parseSkill(dir, string(raw))
		if perr != nil {
			return nil, fmt.Errorf("skills: %s: %w", p, perr)
		}
		// BEHAVIOURAL CASES are loaded on the SAME terms as the method itself
		// (tracker 331): zero cases is a load error, so a new skill cannot ship
		// with ~30 authored conditions and nothing proving any of them fires.
		cases, cerr := loadSkillCases(sk)
		if cerr != nil {
			return nil, fmt.Errorf("skills: %s: %w", sk.Name, cerr)
		}
		sk.Cases = cases
		sk.Origin = SkillOriginCompiled
		if _, dup := set.byName[sk.Name]; dup {
			return nil, fmt.Errorf("skills: duplicate skill %q", sk.Name)
		}
		set.byName[sk.Name] = sk
		set.order = append(set.order, sk.Name)
	}
	sort.Strings(set.order)
	// Whole-set drift check: every `next=` must name a skill that exists.
	if err := validateNextGraph(set); err != nil {
		return nil, err
	}
	// Exactly one entry method, so selection always has a deterministic default.
	methods := 0
	for _, n := range set.order {
		if set.byName[n].Layer == LayerMethod {
			methods++
		}
	}
	if methods != 1 {
		return nil, fmt.Errorf("skills: expected exactly 1 method-layer entry skill, found %d", methods)
	}
	// Whole-set case check: a case may only assert a path the method graph can
	// actually take (skill_cases.go).
	if err := validateCaseGraph(set); err != nil {
		return nil, err
	}
	return set, nil
}

// validateNextGraph is the whole-set `next=` check: every target exists and may be
// reached from where it is named (hopAllowed).
func validateNextGraph(set *SkillSet) error {
	for _, n := range set.order {
		from := set.byName[n]
		for _, d := range from.Decisions {
			if d.Kind != DecisionNext {
				continue
			}
			to, ok := set.byName[d.Target]
			if !ok {
				return fmt.Errorf("skills: %s: decision next=%q names a skill that does not exist", n, d.Target)
			}
			if !hopAllowed(from, to) {
				return fmt.Errorf("skills: %s: decision next=%q may not be reached from here: a compiled method never hands off to a customer's runbook, a runbook only reaches its own tenant's, and a MOP is nobody's next step", n, d.Target)
			}
		}
	}
	return nil
}

// parseSkill splits frontmatter from body and validates one skill.
func parseSkill(dir, raw string) (*Skill, error) {
	front, body, err := splitSkillFrontmatter(raw)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("body is empty — a skill without prose teaches nothing")
	}
	fields, blocks, err := parseFrontmatter(front)
	if err != nil {
		return nil, err
	}
	sk := &Skill{Body: strings.TrimSpace(body)}

	sk.Kind = SkillKind(strings.TrimSpace(fields["kind"]))
	switch sk.Kind {
	case "":
		sk.Kind = SkillKindInvestigative
	case SkillKindInvestigative, SkillKindMOP:
	default:
		return nil, fmt.Errorf("kind %q is not one of %s, %s", sk.Kind, SkillKindInvestigative, SkillKindMOP)
	}
	if err := parseSkillSteps(sk, fields, blocks); err != nil {
		return nil, err
	}

	sk.Name = strings.TrimSpace(fields["name"])
	switch {
	case sk.Name == "":
		return nil, fmt.Errorf("name is required")
	case !reSkillName.MatchString(sk.Name):
		return nil, fmt.Errorf("name %q must match %s", sk.Name, reSkillName)
	case sk.Name != dir:
		return nil, fmt.Errorf("name %q must equal its directory %q", sk.Name, dir)
	}

	sk.Layer = SkillLayer(strings.TrimSpace(fields["layer"]))
	if !validSkillLayer(sk.Layer) {
		return nil, fmt.Errorf("layer %q is not one of %v", sk.Layer, skillLayerOrder)
	}

	v, verr := strconv.Atoi(strings.TrimSpace(fields["version"]))
	if verr != nil || v < 1 {
		return nil, fmt.Errorf("version must be an integer >= 1 (got %q)", fields["version"])
	}
	sk.Version = v

	sk.WhenToUse = lowerList(splitCommaList(fields["when_to_use"]))
	if len(sk.WhenToUse) == 0 {
		return nil, fmt.Errorf("when_to_use is required — a skill that never matches is dead weight")
	}
	sk.SymptomKinds = lowerList(splitCommaList(fields["symptom_kinds"]))
	if len(sk.SymptomKinds) == 0 {
		return nil, fmt.Errorf("symptom_kinds is required")
	}

	sk.Tools = splitCommaList(fields["tools"])
	if len(sk.Tools) == 0 && !sk.isMOP() {
		return nil, fmt.Errorf("tools is required — declare the skill's read-only allowlist")
	}
	declared := make(map[string]bool, len(sk.Tools))
	for _, t := range sk.Tools {
		if !skillToolAllowlist[t] {
			return nil, fmt.Errorf("tool %q is not on the skill tool allowlist (read-only tools only)", t)
		}
		if _, ok := toolMetas[t]; !ok {
			return nil, fmt.Errorf("tool %q has no declared argument schema (toolspec.go)", t)
		}
		declared[t] = true
	}

	if err := parseAppliesWhen(sk, fields, blocks); err != nil {
		return nil, err
	}

	sk.LookFor = blocks["look_for"]
	if len(sk.LookFor) == 0 {
		return nil, fmt.Errorf("look_for is required")
	}

	for _, line := range blocks["gather"] {
		step, gerr := parseGatherStep(line, declared)
		if gerr != nil {
			return nil, fmt.Errorf("gather %q: %w", line, gerr)
		}
		sk.Gather = append(sk.Gather, step)
	}
	if len(sk.Gather) == 0 && !sk.isMOP() {
		return nil, fmt.Errorf("gather is required — a skill must say what evidence it collects")
	}
	if len(sk.Gather) > MaxSkillToolCalls {
		return nil, fmt.Errorf("gather declares %d steps; the per-turn tool budget is %d", len(sk.Gather), MaxSkillToolCalls)
	}
	if err := validateMemoryOrder(sk.Gather); err != nil {
		return nil, err
	}

	for _, line := range blocks["decisions"] {
		d, derr := parseDecision(line, declared)
		if derr != nil {
			return nil, fmt.Errorf("decisions %q: %w", line, derr)
		}
		sk.Decisions = append(sk.Decisions, d)
	}
	if len(sk.Decisions) == 0 {
		return nil, fmt.Errorf("decisions is required — a skill must say where it hands off")
	}
	hasVerdict := false
	for _, d := range sk.Decisions {
		if d.Kind == DecisionVerdict {
			hasVerdict = true
		}
	}
	if !hasVerdict {
		return nil, fmt.Errorf("decisions must include a verdict= line stating what a conclusion says")
	}
	if sk.isMOP() && len(sk.NextSkills()) > 0 {
		return nil, fmt.Errorf("a %s hands off to nothing: nothing runs one, so a next= line could never be taken", SkillKindMOP)
	}
	return sk, nil
}

// parseAppliesWhen reads the comma-separated `applies_when:` scalar. Only
// `fact:` conditions are allowed (it is a statement about the DEVICE, decided
// before anything is gathered), and a MOP may not carry one: nothing selects a
// MOP, so the line could never be evaluated.
func parseAppliesWhen(sk *Skill, fields map[string]string, blocks map[string][]string) error {
	if _, block := blocks["applies_when"]; block {
		return fmt.Errorf("applies_when: takes a comma-separated list of %s conditions, not a block", CondFactPrefix)
	}
	raw, ok := fields["applies_when"]
	if !ok {
		return nil
	}
	if sk.isMOP() {
		return fmt.Errorf("applies_when: belongs to an %s method — nothing selects a %s", SkillKindInvestigative, SkillKindMOP)
	}
	seen := map[string]bool{}
	for _, part := range splitCommaList(raw) {
		key, _, _ := strings.Cut(part, "=")
		if !strings.HasPrefix(strings.TrimSpace(key), CondFactPrefix) {
			return fmt.Errorf("applies_when %q: only %s<key>=<value> conditions are allowed", part, CondFactPrefix)
		}
		c, err := parseSkillCondition(part, nil)
		if err != nil {
			return fmt.Errorf("applies_when: %w", err)
		}
		if seen[c.Key] {
			return fmt.Errorf("applies_when names %s twice — join the values with %q", c.Key, factValueAlt)
		}
		seen[c.Key] = true
		sk.AppliesWhen = append(sk.AppliesWhen, c)
	}
	if len(sk.AppliesWhen) == 0 {
		return fmt.Errorf("applies_when: is empty — omit the line for a method that applies everywhere")
	}
	return nil
}

// parseSkillSteps reads the steps: block, which only a MOP has and every MOP must.
func parseSkillSteps(sk *Skill, fields map[string]string, blocks map[string][]string) error {
	_, scalar := fields["steps"]
	_, block := blocks["steps"]
	if !sk.isMOP() {
		if scalar || block {
			return fmt.Errorf("steps: belongs to kind: %s — an %s method gathers, it has no steps", SkillKindMOP, SkillKindInvestigative)
		}
		return nil
	}
	if scalar {
		return fmt.Errorf("steps: takes a list of \"  - \" items, not a value")
	}
	sk.Steps = blocks["steps"]
	if len(sk.Steps) == 0 {
		return fmt.Errorf("kind: %s requires a steps: block (1-%d lines)", SkillKindMOP, maxMOPSteps)
	}
	if len(sk.Steps) > maxMOPSteps {
		return fmt.Errorf("steps: declares %d lines; a %s has at most %d", len(sk.Steps), SkillKindMOP, maxMOPSteps)
	}
	return nil
}

// splitSkillFrontmatter returns the text between the leading `---` fence and
// the closing one, plus everything after it. Named apart from docs_index.go's
// splitFrontmatter: that one parses the docs corpus's own (different) header
// dialect and returns a parsed map — the two must not be confused.
func splitSkillFrontmatter(raw string) (front, body string, err error) {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return "", "", fmt.Errorf("file must start with a --- frontmatter fence")
	}
	rest := s[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		return "", "", fmt.Errorf("frontmatter fence is not closed")
	}
	return rest[:end], rest[end+len("\n---\n"):], nil
}

// parseFrontmatter reads the strict dialect: `key: value` scalars and `key:` +
// two-space `  - item` blocks. Anything else is an error, so a typo cannot be
// silently dropped.
func parseFrontmatter(front string) (fields map[string]string, blocks map[string][]string, err error) {
	fields = map[string]string{}
	blocks = map[string][]string{}
	current := ""
	for i, line := range strings.Split(front, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "  - ") {
			if current == "" {
				return nil, nil, fmt.Errorf("line %d: list item outside a block key", i+1)
			}
			item := strings.TrimSpace(line[len("  - "):])
			if item == "" {
				return nil, nil, fmt.Errorf("line %d: empty list item", i+1)
			}
			blocks[current] = append(blocks[current], item)
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return nil, nil, fmt.Errorf("line %d: unexpected indentation (list items use exactly \"  - \")", i+1)
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			return nil, nil, fmt.Errorf("line %d: expected \"key: value\" or \"key:\"", i+1)
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		if _, dup := fields[key]; dup {
			return nil, nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		if _, dup := blocks[key]; dup {
			return nil, nil, fmt.Errorf("line %d: duplicate key %q", i+1, key)
		}
		if val == "" {
			blocks[key] = nil
			current = key
			continue
		}
		fields[key] = val
		current = ""
	}
	return fields, blocks, nil
}

var reGatherCall = regexp.MustCompile(`^([a-z0-9_]+)\((.*)\)$`)

// parseGatherStep parses `tool(arg, k=v)` and validates it against the tool's
// declared argument schema (toolspec.go) and the skill's own allowlist.
func parseGatherStep(line string, declared map[string]bool) (GatherStep, error) {
	m := reGatherCall.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return GatherStep{}, fmt.Errorf("expected tool(arg, key=value)")
	}
	step := GatherStep{Tool: m[1], Bind: map[string]string{}, Args: map[string]string{}, Strict: map[string]bool{}}
	if !declared[step.Tool] {
		return GatherStep{}, fmt.Errorf("tool %q is not in this skill's tools: list", step.Tool)
	}
	meta := toolMetas[step.Tool]
	argOK := make(map[string]bool, len(meta.args))
	for _, a := range meta.args {
		argOK[a.name] = true
	}
	for _, part := range strings.Split(m[2], ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, isLiteral := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if !argOK[name] {
			return GatherStep{}, fmt.Errorf("%q is not a declared argument of %s", name, step.Tool)
		}
		if _, dup := step.Bind[name]; dup {
			return GatherStep{}, fmt.Errorf("argument %q given twice", name)
		}
		if _, dup := step.Args[name]; dup {
			return GatherStep{}, fmt.Errorf("argument %q given twice", name)
		}
		if isLiteral {
			v := strings.TrimSpace(value)
			if v == "" {
				return GatherStep{}, fmt.Errorf("literal %q has an empty value", name)
			}
			// `arg=@entity` binds the argument from a DIFFERENTLY NAMED
			// server-resolved entity (target=@prefix). It is still a bind — the
			// value comes from the server, never from the skill text or the model.
			if ent, isBind := strings.CutPrefix(v, "@"); isBind {
				if !skillEntities[ent] {
					return GatherStep{}, fmt.Errorf("%q binds @%s, which is not a resolvable entity (%v)", name, ent, sortedKeys(skillEntities))
				}
				step.Bind[name] = ent
				step.Strict[name] = true
				continue
			}
			step.Args[name] = v
			continue
		}
		if !skillEntities[name] {
			return GatherStep{}, fmt.Errorf("%q is not a resolvable entity (%v)", name, sortedKeys(skillEntities))
		}
		step.Bind[name] = name
	}
	// Every REQUIRED argument must be satisfiable, or the step could only ever
	// fail at runtime.
	for _, a := range meta.args {
		if !a.required {
			continue
		}
		if _, bound := step.Bind[a.name]; bound {
			continue
		}
		if _, lit := step.Args[a.name]; lit {
			continue
		}
		return GatherStep{}, fmt.Errorf("required argument %q of %s is neither bound nor literal", a.name, step.Tool)
	}
	return step, nil
}

// parseDecision parses `kind=target [when <condition|reason>]` / `kind=reason`.
func parseDecision(line string, declared map[string]bool) (SkillDecision, error) {
	kindRaw, rest, ok := strings.Cut(strings.TrimSpace(line), "=")
	if !ok {
		return SkillDecision{}, fmt.Errorf("expected kind=…")
	}
	kind := SkillDecisionKind(strings.TrimSpace(kindRaw))
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return SkillDecision{}, fmt.Errorf("decision has no content")
	}
	switch kind {
	case DecisionNext:
		target, reason, _ := strings.Cut(rest, " ")
		target = strings.TrimSpace(target)
		if !reSkillName.MatchString(target) {
			return SkillDecision{}, fmt.Errorf("next= must name a skill (got %q)", target)
		}
		reason = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(reason), "when "))
		// A machine condition is the FIRST word of the reason when that word
		// carries an `=`. It must then parse against the closed vocabulary: a
		// mistyped key fails the build rather than becoming a rule that can
		// never fire. Everything after it is the human reason.
		head, tail, _ := strings.Cut(reason, " ")
		if strings.Contains(head, "=") {
			cond, cerr := parseSkillCondition(head, declared)
			if cerr != nil {
				return SkillDecision{}, cerr
			}
			human := strings.TrimSpace(tail)
			if human == "" {
				human = cond.Human()
			}
			return SkillDecision{Kind: kind, Target: target, Reason: human, Cond: &cond}, nil
		}
		return SkillDecision{Kind: kind, Target: target, Reason: reason}, nil
	case DecisionVerdict, DecisionEscalate:
		return SkillDecision{Kind: kind, Reason: rest}, nil
	default:
		return SkillDecision{}, fmt.Errorf("kind %q must be next, verdict or escalate", kind)
	}
}

func splitCommaList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func lowerList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	return out
}

// sortedKeysOfMaps lists a facet map's keys in sorted order.
func sortedKeysOfMaps(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
