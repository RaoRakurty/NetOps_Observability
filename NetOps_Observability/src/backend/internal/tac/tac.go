// Package tac is the TAC ESCALATION PACK: the closed issue-class taxonomy, the
// per-dialect command plans, the read-only collection that runs them, and the
// redacted evidence bundle a vendor TAC engineer can actually work from.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md. The knowledge is
// DATA (ai/tac/classes.yaml + ai/tac/plans/<dialect>.yaml, schema in
// ai/tac/README.md); this package is the engine that validates, selects, runs
// and packages it. Adding a class or a vendor is a data change reviewed like a
// skill — never a code change.
//
// THE FIVE THINGS IT DOES
//
//	Classify  incident evidence      → issue class + why + alternatives
//	Plan      class + device dialect → the command plan, unbound intents named
//	Collect   plan                   → read-only capture through the SSH gateway
//	Bundle    capture + evidence     → the redacted zip a case is opened with
//	CaseOpener                       → portal text now, connectors in W2
//
// SAFETY (§8, and it is the reason this package exists as a closed system):
// three independent guards stand between a plan file and a device. The LOADER
// refuses any command that is not a read-only show (protocoldiag.ValidateReadOnly)
// and any placeholder outside the closed grammar. The GATE refuses, at run time,
// any command that is not a rendering of an authored template for THAT device's
// dialect. The RUNNER (internal/protocoldiag's SSHCommandRunner, reused whole)
// re-validates the shape, holds one collection per device, and bounds every
// command's time and output. None of the three is redundant: they fail closed at
// different moments and for different reasons.
//
// ZERO TRUST (§3/§3a): nothing here trusts a request body. The subject device is
// resolved upstream in the caller's own scope and its tenant is STAMPED onto
// every plan, capture and bundle; bundles are stored under a tenant-keyed
// directory tree; the problem statement is written from EVIDENCE IDS the caller
// already owns and never from free text a client supplied.
//
// LLM (§15): the problem statement may be written through the Iris orchestrator,
// but Iris NEVER chooses what to run. It is handed a closed evidence set and a
// server-controlled instruction, and its output is treated as untrusted text —
// every sentence must cite an evidence id that was in the input, or the
// deterministic template is used instead. There is no tool loop here.
package tac

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// Version is the pinned stamp for this engine's behaviour. The DATA carries its
// own version (Catalog.Version, DialectPlan.Version); both are written into
// every bundle MANIFEST so a bundle is replayable against exactly what produced
// it.
const Version = "correlix-tac-2026-09-05"

// ── closed enums ────────────────────────────────────────────────────────────

// intentAreas is the CLOSED first segment of an intent id. Adding an area is a
// code change on purpose: an area is a promise that the plan preview, the
// coverage view and a reviewer all understand the concept, and it is the one
// thing in the intent vocabulary that a research merge cannot invent for itself.
//
// It grew from 20 to this list when the vendor research corpus was merged
// (2026-09-05): these are the areas its 3,000-odd cited command entries actually
// use, each a real network concept a TAC engineer would name. The list is long
// because networks are; it is still closed, and scripts/tac-merge-research.py
// REFUSES a research record whose intent falls outside it.
var intentAreas = map[string]struct{}{
	// core, from the original W1 vocabulary
	"system": {}, "interface": {}, "optics": {}, "route": {}, "fib": {},
	"arp": {}, "l2": {}, "stp": {}, "ospf": {}, "isis": {}, "bgp": {},
	"mpls": {}, "overlay": {}, "mlag": {}, "qos": {}, "hardware": {},
	"logging": {}, "config": {}, "tech": {}, "platform": {},
	// routing and forwarding
	"rib": {}, "rpf": {}, "cef": {}, "forwarding": {}, "routing": {}, "rpl": {},
	"ospfv3": {}, "eigrp": {}, "pim": {}, "igmp": {}, "igmpsnoop": {}, "mroute": {},
	"mrib": {}, "mfib": {}, "multicast": {}, "bfd": {}, "vrf": {}, "l3vpn": {},
	"sr": {}, "te": {}, "rsvp": {}, "ldp": {}, "clns": {}, "path": {},
	"policyroute": {}, "nd": {}, "ip": {}, "icmp": {}, "pathmtu": {},
	"reachability": {}, "connectivity": {}, "tcp": {}, "dns": {}, "neighbor": {},
	// layer 2 and the fabric
	"vlan": {}, "vxlan": {}, "evpn": {}, "lag": {}, "lacp": {}, "pagp": {},
	"portchannel": {}, "trunk": {}, "vpc": {}, "mac": {}, "bridge": {},
	"switchport": {}, "vtp": {}, "udld": {}, "stormcontrol": {}, "portsecurity": {},
	"errdisable": {}, "fabric": {}, "underlay": {}, "l2fm": {}, "ethpm": {},
	"vrrp": {}, "vrrpv3": {}, "hsrp": {}, "fhrp": {}, "varp": {}, "stack": {},
	// platform, hardware and health
	"cpu": {}, "memory": {}, "buffer": {}, "process": {}, "processes": {},
	"environment": {}, "env": {}, "chassis": {}, "module": {}, "asic": {}, "npu": {},
	"np": {}, "hw": {}, "fpd": {}, "poe": {}, "cable": {}, "transceiver": {},
	"alarms": {}, "obfl": {}, "crash": {}, "cores": {}, "core": {}, "watchdog": {},
	"filesystem": {}, "storage": {}, "file": {}, "files": {}, "boot": {},
	"redundancy": {}, "reload": {}, "uptime": {}, "version": {}, "inventory": {},
	"install": {}, "software": {}, "update": {}, "license": {}, "jobs": {},
	"punt": {}, "lpts": {}, "copp": {}, "cpp": {}, "ddos": {}, "ratelimiter": {},
	"pie": {}, "vc": {},
	// services, management and security
	"aaa": {}, "auth": {}, "user": {}, "security": {}, "acl": {}, "policy": {},
	"firewall": {}, "nat": {}, "session": {}, "vpn": {}, "ipsec": {}, "tunnel": {},
	"proxy": {}, "utm": {}, "ztna": {}, "decryption": {}, "sdwan": {}, "linkmonitor": {},
	"ha": {}, "dhcp": {}, "ntp": {}, "clock": {}, "snmp": {}, "log": {},
	"audit": {}, "eventmonitor": {}, "mgmt": {}, "network": {}, "agent": {},
	"extensions": {}, "cli": {}, "transport": {}, "service": {}, "dataplane": {},
	"capture": {}, "diag": {}, "techsupport": {}, "support": {}, "admin": {},
	"panorama": {}, "fortiguard": {}, "feature": {}, "ssh-server": {},
}

// classProtocols is the CLOSED grouping enum. It only groups a class in the UI;
// detection never keys on it.
var classProtocols = map[string]struct{}{
	"bgp": {}, "ospf": {}, "isis": {}, "interface": {}, "l2": {}, "overlay": {},
	"mpls": {}, "qos": {}, "hardware": {}, "system": {}, "config": {}, "generic": {},
}

// Verified is the honesty label on a command binding.
type Verified string

const (
	// VerifiedCapture — this exact command shape has been run on this platform
	// and returned what we expect.
	VerifiedCapture Verified = "capture"
	// VerifiedDocClaimed — taken from the vendor's published documentation and
	// never executed here. Shown to the operator, and stamped in the MANIFEST,
	// as "documented, not verified".
	VerifiedDocClaimed Verified = "doc_claimed"
)

// placeholders is the CLOSED substitution vocabulary a plan command may carry.
// A `{token}` outside this set is treated as a LITERAL, so a typo fails closed
// (the command never matches the gate) rather than opening a wildcard. This
// mirrors internal/protocoldiag/commandtable.go deliberately.
var placeholders = map[string]struct{}{
	"{if}": {}, "{peer}": {}, "{prefix}": {}, "{vrf-scope}": {},
	"{rid}": {}, "{area}": {}, "{vlan}": {}, "{vni}": {},
}

// vrfQualifiers are the dialect keywords a {vrf-scope} may emit ahead of the
// instance name.
var vrfQualifiers = map[string]struct{}{
	"vrf": {}, "instance": {}, "vpn-instance": {}, "routing-instance": {},
}

// GenericClassID is the mandatory fallback class: baseline only, no detection.
// An incident nothing matched escalates as this, and says so.
const GenericClassID = "generic"

// ── id grammars ─────────────────────────────────────────────────────────────

var (
	slugRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	// An intent is <area>.<object>[.<qualifier>[.<qualifier>]]. Segments after
	// the area may carry `_` as a word separator: the merged vendor corpus uses
	// it for compound objects ("bgp.neighbors.reset_reason"), and rejecting it
	// would have meant renaming cited research rather than reading it.
	intentRE = regexp.MustCompile(`^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9_-]*){1,3}$`)
	// argTokenRE is the shape ONE substituted argument may take. Deliberately
	// narrow — no whitespace, no quoting, none of the CLI metacharacters
	// ValidateReadOnly rejects.
	argTokenRE = regexp.MustCompile(`^[A-Za-z0-9._:/+@,%\[\]-]{1,128}$`)
)

// ── errors ──────────────────────────────────────────────────────────────────

var (
	// ErrUnknownClass is an issue-class id the taxonomy does not carry.
	ErrUnknownClass = errors.New("tac: unknown issue class")
	// ErrNoPlan is a dialect with no authored command plan — the HONEST path,
	// not a failure: the caller shows "no authored plan for this platform" and
	// offers the paste fallback.
	ErrNoPlan = errors.New("tac: no authored command plan for this platform")
	// ErrCommandNotInPlan is the closed-table refusal at run time.
	ErrCommandNotInPlan = errors.New("tac: command is not in the authored plan for this dialect")
	// ErrCollectBusy is the one-collection-per-device refusal.
	ErrCollectBusy = errors.New("tac: a TAC collection is already running on this device")
	// errTACCatalogUnavailable is a nil catalog: the embedded data did not load.
	// It cannot happen from a deployment condition (the data is embedded and the
	// package's own test parses it in CI), so it is a bug in the data, reported
	// rather than dereferenced.
	errTACCatalogUnavailable = errors.New("tac: the escalation catalog is not available on this build")
	// ErrNoRunner is the honest "no capture transport on this deployment"
	// condition — a 503, never a fabricated capture.
	ErrNoRunner = errors.New("tac: no read-only command runner is configured on this deployment")
)

// ── data model ──────────────────────────────────────────────────────────────

// Source is one citation. A doc_claimed binding must carry at least one.
type Source struct {
	Title     string `json:"title"`
	URL       string `json:"url"`
	Retrieved string `json:"retrieved,omitempty"`
}

// Intent is one vendor-neutral command CONCEPT.
type Intent struct {
	ID    string `json:"id"`
	Area  string `json:"area"`
	Title string `json:"title"`
	Note  string `json:"note,omitempty"`
}

// Detect is a class's evidence → class map. Every id in it must already exist in
// the repo; the loader cannot check that (the ids live in other packages and in
// Python), so a REPO-LEVEL test does — see reference_test.go.
type Detect struct {
	Alerts     []string `json:"alerts,omitempty"`
	Hypotheses []string `json:"hypotheses,omitempty"`
	Signatures []string `json:"signatures,omitempty"`
	Skills     []string `json:"skills,omitempty"`
	Issues     []string `json:"issues,omitempty"`
	LogRegex   []string `json:"log_regex,omitempty"`

	logRE []*regexp.Regexp
}

// empty reports a class with no detection rules at all (only `generic` may).
func (d Detect) empty() bool {
	return len(d.Alerts) == 0 && len(d.Hypotheses) == 0 && len(d.Signatures) == 0 &&
		len(d.Skills) == 0 && len(d.Issues) == 0 && len(d.LogRegex) == 0
}

// Class is one issue class in the closed (but data-extensible) taxonomy.
type Class struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Protocol     string   `json:"protocol"`
	Summary      string   `json:"summary,omitempty"`
	TACFirstLook string   `json:"tac_first_look,omitempty"`
	Detect       Detect   `json:"detect"`
	Intents      []string `json:"intents"`
	Sources      []Source `json:"sources,omitempty"`
}

// Binding is one dialect's command for one intent.
type Binding struct {
	Intent   string        `json:"intent"`
	Command  string        `json:"command"`
	Verified Verified      `json:"verified"`
	Sources  []Source      `json:"sources,omitempty"`
	MaxBytes int64         `json:"max_bytes,omitempty"`
	Timeout  time.Duration `json:"-"`
	// Consent marks a command the vendor's own documentation says is NOT routine
	// — it writes a file on the device, dumps a core, or measurably loads the
	// control plane (SR OS `admin tech-support`, Huawei
	// `display diagnostic-information <file>`, SR Linux `tech-support`). It is
	// NEVER in a baseline, is never run unless the operator opts in, and the
	// plan preview carries the vendor's caveat verbatim.
	Consent bool `json:"consent,omitempty"`
	// ConsentNote is the vendor's own words about why it needs consent.
	ConsentNote string `json:"consent_note,omitempty"`
	// ReadOnlyException is the CITED reason this command is a documented status
	// READ despite carrying a token the read-only grammar refuses on sight —
	// FortiOS spells several pure status prints `diagnose debug …`. It is the
	// per-dialect allowlist the design calls for, and it is DATA: the exception
	// is written down, next to the command, with the source that establishes it,
	// and everything without one still fails closed. An exception without a
	// citation is a load error.
	ReadOnlyException string `json:"read_only_exception,omitempty"`

	// tokens is the command's template token list, precompiled for the gate.
	tokens []string
}

// DialectPlan is one CLI dialect's authored command set.
type DialectPlan struct {
	Dialect  string             `json:"dialect"`
	Profile  string             `json:"profile"`
	Display  string             `json:"display"`
	Version  string             `json:"version"`
	Sources  []Source           `json:"sources,omitempty"`
	Baseline []string           `json:"baseline"`
	Optional []string           `json:"optional,omitempty"`
	Bindings map[string]Binding `json:"bindings"`
}

// Bound reports whether this dialect binds intent.
func (p *DialectPlan) Bound(intent string) (Binding, bool) {
	if p == nil {
		return Binding{}, false
	}
	b, ok := p.Bindings[intent]
	return b, ok
}

// Catalog is the loaded, immutable taxonomy + plan set. It is built once and
// never mutated, so it is safe to share across goroutines (§5: no globals, no
// hidden singletons — the process holds one and injects it).
type Catalog struct {
	Version     string
	intents     map[string]Intent
	intentOrder []string
	classes     map[string]Class
	classOrder  []string
	plans       map[string]*DialectPlan
	planOrder   []string
}

// Classes returns every class in authoring order.
func (c *Catalog) Classes() []Class {
	out := make([]Class, 0, len(c.classOrder))
	for _, id := range c.classOrder {
		out = append(out, c.classes[id])
	}
	return out
}

// Class looks one up.
func (c *Catalog) Class(id string) (Class, bool) {
	cl, ok := c.classes[id]
	return cl, ok
}

// Intents returns the vocabulary in authoring order.
func (c *Catalog) Intents() []Intent {
	out := make([]Intent, 0, len(c.intentOrder))
	for _, id := range c.intentOrder {
		out = append(out, c.intents[id])
	}
	return out
}

// Intent looks one up.
func (c *Catalog) Intent(id string) (Intent, bool) {
	in, ok := c.intents[id]
	return in, ok
}

// Dialects returns the dialect slugs that have an authored plan, sorted.
func (c *Catalog) Dialects() []string { return append([]string(nil), c.planOrder...) }

// PlanFor returns a dialect's authored plan. ok=false is the honest "no authored
// plan for this platform" path, never an error to hide.
func (c *Catalog) PlanFor(dialect string) (*DialectPlan, bool) {
	p, ok := c.plans[dialect]
	return p, ok
}

// tokenize splits a command template into tokens for the gate.
func tokenize(cmd string) []string { return strings.Fields(cmd) }
