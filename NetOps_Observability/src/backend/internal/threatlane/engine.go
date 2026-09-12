// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package threatlane

import (
	"context"
	"sort"
	"time"

	"netops/backend/internal/secfindings"
)

// Engine runs the threat-detection catalog over device logs and flows pulled
// from injected sources, and returns "signal" findings. Both externals are
// injected as interfaces (§5) so the engine is a pure, deterministic, testable
// producer with no hidden coupling and no shared mutable state (safe under -race
// by construction: it starts no goroutines and mutates nothing package-level).
type Engine struct {
	catalog *Catalog
	logSrc  LogSource
	flowSrc FlowSource
	scanID  string
	now     func() time.Time
}

// Option configures an Engine.
type Option func(*Engine)

// WithClock injects the time source (default time.Now). Tests pin it for
// deterministic timestamps on flow findings whose group carries no event time.
func WithClock(now func() time.Time) Option {
	return func(e *Engine) {
		if now != nil {
			e.now = now
		}
	}
}

// WithScanID stamps an assessment-run id onto every finding (Finding.ScanID),
// which secbus folds into the deterministic signal identity. Optional.
func WithScanID(id string) Option {
	return func(e *Engine) { e.scanID = id }
}

// NewEngine builds an Engine. catalog, logSrc and flowSrc MUST be non-nil;
// passing nil is a programming error the caller must avoid (the engine does not
// paper over a missing dependency with a silent no-op — fail closed).
func NewEngine(catalog *Catalog, logSrc LogSource, flowSrc FlowSource, opts ...Option) *Engine {
	e := &Engine{catalog: catalog, logSrc: logSrc, flowSrc: flowSrc, now: time.Now}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Detect runs the full catalog and returns the findings that fired, in a
// deterministic total order.
//
// FAIL-CLOSED: if either source returns an error the whole run fails (nil, err)
// so the caller surfaces "unassessed" — a source failure is NEVER swallowed into
// a (falsely clean) empty result. A healthy source with no events simply yields
// no findings from that family, which is the honest "evaluated, nothing tripped"
// outcome for a signal lane (absence of a finding is not a green claim).
func (e *Engine) Detect(ctx context.Context) ([]secfindings.Finding, error) {
	logs, err := e.logSrc.LogEvents(ctx)
	if err != nil {
		return nil, err
	}
	flows, err := e.flowSrc.Flows(ctx)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var out []secfindings.Finding
	out = append(out, e.runLogRules(logs)...)
	out = append(out, e.runFlowRules(flows)...)

	sortFindings(out)
	return out, nil
}

// runLogRules applies every device-log rule to every normalized log event.
func (e *Engine) runLogRules(logs []LogEvent) []secfindings.Finding {
	var out []secfindings.Finding
	for _, ev := range logs {
		// Normalize ONCE per event, not once per rule: every log rule matches
		// over the same lowercased mnemonic+message, and recomputing it inside
		// each rule made the lane O(rules × events) string allocations for a
		// value that cannot change between rules (ultra-review #45, tracker
		// 208d). `ev` is already this loop's own copy, so this mutates nothing
		// the caller can see.
		ev = ev.withNormalized()
		for _, rule := range e.catalog.logRules {
			res := rule.Detect(ev)
			if !res.Tripped {
				continue
			}
			f := e.baseFinding(CategoryDeviceLog, ev.TenantID, logResource(ev), e.logTime(ev))
			f.RawRuleID = rule.ID
			f.ControlID = rule.Technique
			f.ControlTitle = rule.Title
			f.Standards = standardsFor(rule.Technique, rule.Controls)
			f.Severity = rule.Severity
			f.Observed = res.Evidence
			f.Intended = rule.Intended
			f.Remediation = rule.Remediation
			f.Detail = techniqueDetail(rule.Technique, rule.TechniqueName)
			f.EvidenceRef = logEvidenceRef(ev, rule.ID)
			f.ID = f.RawRuleID + ":" + f.Resource.DeviceID + ":" + ev.Mnemonic
			f.SetStatus(rule.Verdict)
			out = append(out, f)
		}
	}
	return out
}

// runFlowRules groups flows into conversations + source views and applies the
// behavioral rules. Grouping and iteration are ordered so the output is
// deterministic (no map-iteration nondeterminism).
func (e *Engine) runFlowRules(flows []FlowRecord) []secfindings.Finding {
	if len(flows) == 0 {
		return nil
	}
	convs, sources := groupFlows(flows)

	var out []secfindings.Finding
	for _, c := range convs {
		for _, rule := range e.catalog.pairRules {
			res := rule.Detect(c)
			if !res.Tripped {
				continue
			}
			f := e.baseFinding(CategoryFlow, c.TenantID, flowResource(c.DeviceID, c.Hostname), e.convTime(c.Flows))
			f.RawRuleID = rule.ID
			f.ControlID = rule.Technique
			f.ControlTitle = rule.Title
			f.Standards = standardsFor(rule.Technique, rule.Controls)
			f.Severity = rule.Severity
			f.Observed = res.Evidence
			f.Intended = rule.Intended
			f.Remediation = rule.Remediation
			f.Detail = techniqueDetail(rule.Technique, rule.TechniqueName)
			f.EvidenceRef = flowEvidenceRef(c.Src+"->"+c.Dst, rule.ID)
			f.ID = f.RawRuleID + ":" + f.Resource.DeviceID + ":" + c.Src + "->" + c.Dst
			f.SetStatus(rule.Verdict)
			out = append(out, f)
		}
	}
	for _, v := range sources {
		for _, rule := range e.catalog.sourceRules {
			res := rule.Detect(v)
			if !res.Tripped {
				continue
			}
			f := e.baseFinding(CategoryFlow, v.TenantID, flowResource(v.DeviceID, v.Hostname), e.convTime(v.Flows))
			f.RawRuleID = rule.ID
			f.ControlID = rule.Technique
			f.ControlTitle = rule.Title
			f.Standards = standardsFor(rule.Technique, rule.Controls)
			f.Severity = rule.Severity
			f.Observed = res.Evidence
			f.Intended = rule.Intended
			f.Remediation = rule.Remediation
			f.Detail = techniqueDetail(rule.Technique, rule.TechniqueName)
			f.EvidenceRef = flowEvidenceRef("src:"+v.Src, rule.ID)
			f.ID = f.RawRuleID + ":" + f.Resource.DeviceID + ":" + v.Src
			f.SetStatus(rule.Verdict)
			out = append(out, f)
		}
	}
	return out
}

// groupFlows buckets flows into (tenant,device,src,dst) conversations and
// (tenant,device,src) source views, both returned in a deterministic order with
// each conversation's flows sorted ascending by start time. Grouping keys are
// built from record fields (§3a: the tenant is the record's, never a request's).
func groupFlows(flows []FlowRecord) ([]Conversation, []SourceView) {
	convMap := map[string]*Conversation{}
	srcMap := map[string]*SourceView{}
	var convKeys, srcKeys []string

	for _, f := range flows {
		ck := f.TenantID + "\x00" + f.DeviceID + "\x00" + f.SrcAddr + "\x00" + f.DstAddr
		c, ok := convMap[ck]
		if !ok {
			c = &Conversation{Src: f.SrcAddr, Dst: f.DstAddr, DeviceID: f.DeviceID, Hostname: f.Hostname, TenantID: f.TenantID}
			convMap[ck] = c
			convKeys = append(convKeys, ck)
		}
		c.Flows = append(c.Flows, f)

		sk := f.TenantID + "\x00" + f.DeviceID + "\x00" + f.SrcAddr
		v, ok := srcMap[sk]
		if !ok {
			v = &SourceView{Src: f.SrcAddr, DeviceID: f.DeviceID, Hostname: f.Hostname, TenantID: f.TenantID}
			srcMap[sk] = v
			srcKeys = append(srcKeys, sk)
		}
		v.Flows = append(v.Flows, f)
	}

	sort.Strings(convKeys)
	sort.Strings(srcKeys)
	convs := make([]Conversation, 0, len(convKeys))
	for _, k := range convKeys {
		c := convMap[k]
		sort.SliceStable(c.Flows, func(i, j int) bool { return c.Flows[i].Start.Before(c.Flows[j].Start) })
		convs = append(convs, *c)
	}
	sources := make([]SourceView, 0, len(srcKeys))
	for _, k := range srcKeys {
		sources = append(sources, *srcMap[k])
	}
	return convs, sources
}

// baseFinding builds the common "signal" finding skeleton.
func (e *Engine) baseFinding(category, tenantID string, res secfindings.Resource, ts time.Time) secfindings.Finding {
	return secfindings.Finding{
		Source:        SourceThreatLane,
		ScanID:        e.scanID,
		Time:          ts,
		TenantID:      tenantID, // §3a: stamped from the source record, never a body
		EvidenceClass: secfindings.EvidenceSignal,
		Category:      category,
		Resource:      res,
	}
}

// logTime returns a non-zero event time for a log finding (secbus rejects a zero
// time). It falls back to the engine clock when the source omitted the time.
func (e *Engine) logTime(ev LogEvent) time.Time {
	if ev.Time.IsZero() {
		return e.now().UTC()
	}
	return ev.Time.UTC()
}

// convTime returns the latest flow start in a group as the finding's event time,
// falling back to the engine clock for an (impossible) empty group.
func (e *Engine) convTime(flows []FlowRecord) time.Time {
	var latest time.Time
	for _, f := range flows {
		if f.Start.After(latest) {
			latest = f.Start
		}
	}
	if latest.IsZero() {
		return e.now().UTC()
	}
	return latest.UTC()
}

func logResource(ev LogEvent) secfindings.Resource {
	// ResolvePlatform stamps the registry-resolved profile id beside the
	// free-form platform hint the log event carried (T9).
	return secfindings.Resource{
		DeviceID:   ev.DeviceID,
		DeviceName: ev.Hostname,
		Hostname:   ev.Hostname,
		Kind:       secfindings.KindNetworkDevice,
		Platform:   ev.Platform,
	}.ResolvePlatform()
}

func flowResource(deviceID, hostname string) secfindings.Resource {
	return secfindings.Resource{
		DeviceID:   deviceID,
		DeviceName: hostname,
		Hostname:   hostname,
		Kind:       secfindings.KindNetworkDevice,
	}
}

// standardsFor builds the finding Standards slice: the ATT&CK tag first, then any
// extra mapped controls the rule carries.
func standardsFor(technique string, controls []string) []string {
	out := make([]string, 0, 1+len(controls))
	out = append(out, attackStandard(technique))
	out = append(out, controls...)
	return out
}

// techniqueDetail renders the operator-facing technique note for Finding.Detail.
func techniqueDetail(technique, name string) string {
	if name == "" {
		return attackTagPrefix + technique
	}
	return attackTagPrefix + technique + " — " + name
}

func logEvidenceRef(ev LogEvent, ruleID string) *secfindings.EvidenceRef {
	return &secfindings.EvidenceRef{
		Locator:        "syslog:" + ev.DeviceID + "#" + ruleID,
		Kind:           "log-event",
		RulesetVersion: RulesetVersion,
	}
}

func flowEvidenceRef(subject, ruleID string) *secfindings.EvidenceRef {
	return &secfindings.EvidenceRef{
		Locator:        "flow:" + subject + "#" + ruleID,
		Kind:           "flow-record",
		RulesetVersion: RulesetVersion,
	}
}

// sortFindings imposes a deterministic total order (§11): evidence class, rule
// id, device id, then the stable per-finding ID. A diff of two runs then
// reflects real change, not iteration order.
func sortFindings(fs []secfindings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.EvidenceClass != b.EvidenceClass {
			return a.EvidenceClass < b.EvidenceClass
		}
		if a.RawRuleID != b.RawRuleID {
			return a.RawRuleID < b.RawRuleID
		}
		if a.Resource.DeviceID != b.Resource.DeviceID {
			return a.Resource.DeviceID < b.Resource.DeviceID
		}
		return a.ID < b.ID
	})
}
