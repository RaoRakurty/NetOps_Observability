// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_activeprobe.go — Iris's active probes (tracker 337 N-I3, design
// item 14): run_ping, run_traceroute, run_dns_test and run_http_test.
//
// Every other Iris tool READS what Correlix already collected. These four take
// one small, fixed measurement NOW, from Correlix's own collector, toward a
// target the workspace owns — an inventory device or a probe the operator
// declared on the Digital Experience page. They never run on a customer device
// and never go through a third-party service (owner rule, 2026-11-13).
//
// Because they originate traffic they are their own risk tier (CapNetProbe):
//
//   - the Policy Engine runs one only when the installation's probe switch, AI
//     investigations and the workspace's own opt-in are all on
//     (PolicyConfig.NetProbes, built per request by the server);
//   - a model never sees one in its manifest and a model-named call is refused
//     (Toolbox.ModelDirected) — they run only as an authored step of a
//     troubleshooting method or an investigation plan (§15 LLM08);
//   - the server resolves the target inside the caller's tenant, refuses
//     loopback / link-local / metadata / multicast space always and internal
//     space unless it is the caller's own device, pins the address, and caps
//     how often one target is probed (internal/probetarget);
//   - the measurement itself is fixed (collectors.RunOneShot): the model picks
//     none of its sizes.
//
// §15: the output names the target by the name the operator gave it, never by
// address; a traceroute reports where replies stop, never the transit routers'
// addresses. Each result is OBSERVED evidence — something Correlix measured a
// moment ago from ONE vantage, which is what the notes say.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ActiveProbeKind is the measurement an active-probe tool takes.
type ActiveProbeKind string

const (
	ProbePing       ActiveProbeKind = "ping"
	ProbeTraceroute ActiveProbeKind = "traceroute"
	ProbeDNS        ActiveProbeKind = "dns"
	ProbeHTTP       ActiveProbeKind = "http"
)

// ActiveProbeCitationPrefix is the citation namespace of active-probe items.
const ActiveProbeCitationPrefix = "probe-now:"

// maxActiveProbeTargets bounds a DNS or web test that re-runs the workspace's
// declared probes: at most this many, failing ones are not preferred — the
// server takes them in catalogue order.
const maxActiveProbeTargets = 3

// maxActiveProbeHops bounds the rendered hops of a traceroute.
const maxActiveProbeHops = 16

// ActiveProbeRequest is a validated ask. Target is an operator-facing name or
// id (an inventory device, or a declared probe); empty means "the workspace's
// declared probes of this kind" for a DNS or web test.
type ActiveProbeRequest struct {
	Kind   ActiveProbeKind
	Target string
}

// ActiveProbeReport is what the server measured for one request.
type ActiveProbeReport struct {
	Kind ActiveProbeKind
	// Scoped is false when no single workspace could be resolved (the platform
	// scope): nothing was sent, and the answer must say why.
	Scoped bool
	// Unavailable says nothing could be measured at all (the collector cannot
	// take this measurement, or no target exists), in operator words.
	Unavailable string
	Results     []ActiveProbeResult
	// TargetsTotal is how many targets matched before the cap.
	TargetsTotal int
	Notes        []string
}

// ActiveProbeHop is one TTL position of a traceroute: whether something
// answered and how fast. Never an address.
type ActiveProbeHop struct {
	TTL     int
	Replied bool
	RTTms   float64
}

// ActiveProbeResult is one target's measurement.
type ActiveProbeResult struct {
	// Target is the name the operator gave the target (a device name or a
	// probe name) — never an address.
	Target     string
	TargetKind string // "device" | "probe"
	// Refused says why this target was not probed (it resolves somewhere
	// Correlix never probes, or its per-target limit was reached).
	Refused string
	// Unavailable says the collector could not take this measurement.
	Unavailable string
	Up          bool
	Sent        int
	Received    int
	LossPct     float64
	RTTms       float64
	Hops        []ActiveProbeHop
	Reached     bool
	StatusCode  int
	FailClass   string
	Answers     int
}

// ── the four tools ─────────────────────────────────────────────────────────

type activeProbeTool struct {
	kind ActiveProbeKind
	deps TroubleshootDeps
}

func (t activeProbeTool) Name() string {
	switch t.kind {
	case ProbePing:
		return "run_ping"
	case ProbeTraceroute:
		return "run_traceroute"
	case ProbeDNS:
		return "run_dns_test"
	default:
		return "run_http_test"
	}
}
func (t activeProbeTool) Module() string         { return "telemetry" }
func (t activeProbeTool) Capability() Capability { return CapNetProbe }

// RequiredPerms: originating traffic is an operation, not a read — the same
// bar as running diagnostic commands (infrastructure:write).
func (t activeProbeTool) RequiredPerms() []string { return []string{"infrastructure:write"} }
func (t activeProbeTool) Freshness() Freshness    { return FreshnessLive }

func (t activeProbeTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	req, err := activeProbeRequestFromArgs(t.kind, args)
	if err != nil {
		return ToolResult{}, err
	}
	rep, err := t.deps.ActiveProbe(ctx, p, req)
	if err != nil {
		return ToolResult{}, err
	}
	return RenderActiveProbe(rep), nil
}

// activeProbeRequestFromArgs validates the arguments. A ping or traceroute
// needs a target; a DNS or web test may re-run the declared probes instead.
func activeProbeRequestFromArgs(kind ActiveProbeKind, args ToolArgs) (ActiveProbeRequest, error) {
	target := strings.TrimSpace(args["target"])
	if target == "" {
		target = strings.TrimSpace(args["device_id"])
	}
	if len(target) > 128 {
		return ActiveProbeRequest{}, fmt.Errorf("target is too long")
	}
	if strings.ContainsAny(target, "\r\n\t") {
		return ActiveProbeRequest{}, fmt.Errorf("target contains a control character")
	}
	if target == "" && (kind == ProbePing || kind == ProbeTraceroute) {
		return ActiveProbeRequest{}, fmt.Errorf("a target device or probe is required")
	}
	return ActiveProbeRequest{Kind: kind, Target: target}, nil
}

// ── rendering ──────────────────────────────────────────────────────────────

// RenderActiveProbe turns a probe report into bounded evidence.
func RenderActiveProbe(rep ActiveProbeReport) ToolResult {
	const href = "#/operations/digital-experience/synthetics"
	tr := ToolResult{}
	item := func(id, text string) {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: ActiveProbeCitationPrefix + string(rep.Kind) + ":" + id, Kind: "metric",
			Text: clampText(text, maxToolTextChars), Href: href,
		})
	}
	what := activeProbeWhat(rep.Kind)
	if !rep.Scoped {
		tr.Notes = append(tr.Notes, "no single workspace is in scope, so nothing was sent — say the "+what+" result is UNKNOWN and that probes run per workspace")
		return tr
	}
	if rep.Unavailable != "" {
		tr.Notes = append(tr.Notes, "the "+what+" did not run: "+rep.Unavailable+" — say the result is UNKNOWN, never that the target is healthy or down")
		tr.Notes = append(tr.Notes, rep.Notes...)
		return tr
	}
	results := rep.Results
	if len(results) > maxActiveProbeTargets {
		results = results[:maxActiveProbeTargets]
		tr.Truncated = true
	}
	for i, r := range results {
		item(strconv.Itoa(i+1), activeProbeLine(rep.Kind, r))
	}
	if total := max(rep.TargetsTotal, len(rep.Results)); total > len(results) {
		tr.Notes = append(tr.Notes, fmt.Sprintf("%d of %d targets were tested (at most %d per test)", len(results), total, maxActiveProbeTargets))
	}
	tr.Notes = append(tr.Notes,
		"this was measured just now from Correlix's own collector — ONE vantage, not the users' machines and not the device itself; a result here does not say what other paths see")
	tr.Notes = append(tr.Notes, rep.Notes...)
	return tr
}

func activeProbeWhat(k ActiveProbeKind) string {
	switch k {
	case ProbePing:
		return "ping"
	case ProbeTraceroute:
		return "traceroute"
	case ProbeDNS:
		return "DNS test"
	default:
		return "web test"
	}
}

// activeProbeLine is one target's rendered result.
func activeProbeLine(k ActiveProbeKind, r ActiveProbeResult) string {
	name := r.Target
	if name == "" {
		name = "the target"
	}
	label := fmt.Sprintf("%s %s from Correlix", activeProbeWhat(k), name)
	switch {
	case r.Refused != "":
		return label + ": not sent — " + r.Refused
	case r.Unavailable != "":
		return label + ": not measured — " + r.Unavailable
	}
	switch k {
	case ProbePing:
		if r.Received == 0 {
			return fmt.Sprintf("%s: no reply to %d of %d echoes (100%% loss)", label, r.Sent, r.Sent)
		}
		return fmt.Sprintf("%s: %d of %d echoes answered (%.0f%% loss), average %.1f ms", label, r.Received, r.Sent, r.LossPct, r.RTTms)
	case ProbeTraceroute:
		return label + ": " + traceSummary(r)
	case ProbeDNS:
		if r.Up {
			addrs := "1 address"
			if r.Answers != 1 {
				addrs = strconv.Itoa(r.Answers) + " addresses"
			}
			return fmt.Sprintf("%s: the name resolved (%s) in %.0f ms", label, addrs, r.RTTms)
		}
		return fmt.Sprintf("%s: the name did not resolve — %s", label, dnsFailWords(r.FailClass))
	default:
		switch {
		case r.StatusCode >= 300 && r.StatusCode < 400:
			return fmt.Sprintf("%s: answered with a redirect (HTTP %d) in %.0f ms — the redirect was not followed", label, r.StatusCode, r.RTTms)
		case r.StatusCode > 0:
			state := "answered"
			if !r.Up {
				state = "answered with an error"
			}
			return fmt.Sprintf("%s: %s, HTTP %d in %.0f ms", label, state, r.StatusCode, r.RTTms)
		default:
			return fmt.Sprintf("%s: no answer — %s", label, httpFailWords(r.FailClass))
		}
	}
}

// traceSummary says how far the replies went, without any address.
func traceSummary(r ActiveProbeResult) string {
	hops := r.Hops
	if len(hops) > maxActiveProbeHops {
		hops = hops[:maxActiveProbeHops]
	}
	lastReply, replies := 0, 0
	for _, h := range hops {
		if h.Replied {
			lastReply, replies = h.TTL, replies+1
		}
	}
	switch {
	case len(hops) == 0:
		return "no hop answered"
	case r.Reached:
		return fmt.Sprintf("the target answered at hop %d (%d of %d hops replied)", lastReply, replies, len(hops))
	case lastReply == 0:
		return fmt.Sprintf("no hop answered in %d hops — the path is blocked at or before the first router, or probes are filtered", len(hops))
	default:
		return fmt.Sprintf("replies stop after hop %d; the target did not answer within %d hops — loss that begins there persists to the destination", lastReply, len(hops))
	}
}

func dnsFailWords(class string) string {
	switch class {
	case "nxdomain":
		return "the resolver answered that the name does not exist"
	case "timeout":
		return "the resolver did not answer in time"
	case "no_answer":
		return "the resolver answered with no address"
	default:
		return "the resolver returned an error"
	}
}

func httpFailWords(class string) string {
	switch class {
	case "tls":
		return "the TLS handshake failed or the certificate did not verify"
	case "connect_refused":
		return "the connection was refused"
	case "reset":
		return "the connection was reset"
	case "timeout":
		return "it did not answer in time"
	default:
		return "the request failed"
	}
}
