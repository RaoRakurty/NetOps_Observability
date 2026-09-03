// Package alerts hosts the rule-driven alert evaluator and the state
// machine that decides when alerts fire, deduplicate, and resolve.
package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/models"
	"netops/backend/notify"
)

// Rule is a single alert rule. The Expr is a PromQL expression that the
// evaluator pushes through to VictoriaMetrics's /api/v1/query.
type Rule struct {
	Name        string            `json:"name"`
	Expr        string            `json:"expr"`
	For         time.Duration     `json:"for"`
	Severity    string            `json:"severity"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Rule's JSON "for" is SECONDS (number) or a Go/Prometheus duration string
// ("5m"). Without these methods encoding/json would treat the raw int64 as
// NANOseconds — the API's `"for": 300` decoded as 300ns and re-encoded file
// rules showed as 3e11 — so both directions are pinned to the documented unit.
func (r Rule) MarshalJSON() ([]byte, error) {
	type bare Rule // method-free alias to avoid marshal recursion
	return json.Marshal(struct {
		bare
		For float64 `json:"for"`
	}{bare(r), r.For.Seconds()})
}

func (r *Rule) UnmarshalJSON(b []byte) error {
	type bare Rule
	aux := struct {
		*bare
		For json.RawMessage `json:"for"`
	}{bare: (*bare)(r)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	if len(aux.For) == 0 || string(aux.For) == "null" {
		r.For = 0
		return nil
	}
	var secs float64
	if err := json.Unmarshal(aux.For, &secs); err == nil {
		if secs < 0 {
			return fmt.Errorf("rule %q: negative 'for'", r.Name)
		}
		r.For = time.Duration(secs * float64(time.Second))
		return nil
	}
	var ds string
	if err := json.Unmarshal(aux.For, &ds); err == nil {
		d, err := time.ParseDuration(ds)
		if err != nil || d < 0 {
			return fmt.Errorf("rule %q: invalid 'for' duration %q", r.Name, ds)
		}
		r.For = d
		return nil
	}
	return fmt.Errorf("rule %q: 'for' must be seconds or a duration string", r.Name)
}

// Engine periodically evaluates every rule against the metric store.
type Engine struct {
	mu        sync.RWMutex
	rules     []Rule
	active    map[string]models.Alert
	pending   map[string]time.Time // alert id → when its condition started holding
	rulesFile string
	notifier  *notify.Dispatcher
	// OnFire, when set, is invoked once per NEWLY-firing alert (not on every tick).
	// The server uses it to ingest an incident; it must be non-blocking/best-effort
	// so the alert loop is never stalled by a downstream consumer.
	OnFire func(models.Alert)
	// OnTransition, when set, is invoked on every state TRANSITION: once when an
	// alert newly fires (firing=true) and once when it resolves (firing=false).
	// The server uses it to fold firings into alert episodes. It runs BEFORE the
	// notification decision for a firing alert, so episode-level suppression
	// (mute/snooze) sees the freshly-folded episode. Best-effort contract like
	// OnFire: it must never block.
	OnTransition func(a models.Alert, firing bool)
	// SuppressNotify, when set, is consulted once per NEWLY-firing alert; true
	// suppresses the outbound NOTIFICATION for that firing (episode mute/snooze).
	// It suppresses noise only: the alert stays in the active set, OnFire still
	// runs (incident ingest is not a notification), and the API still serves it.
	SuppressNotify func(models.Alert) bool
	// dispatched tracks the active alert ids whose FIRE notification actually
	// went out, so a resolve notification is sent only when its counterpart fire
	// was — a suppressed firing must not emit a dangling resolve.
	dispatched map[string]bool
	// TenantOf derives the OWNING TENANT of an alert for the durable notified
	// set (notifystate.go). The server wires it to the same device→tenant
	// derivation the episode fold uses; nil means every alert is platform-owned
	// (tenant ""), which is the correct default for a stack with no inventory.
	// It is never derived from the alert's own labels (§3a rule 2).
	TenantOf func(models.Alert) string
	// notifyState is the DURABLE half of `dispatched`. Without it a restart
	// forgot every notification ever sent and re-paged every still-firing alert
	// on the next tick — observed live 2026-09-03 across two deploys in an
	// hour. nil = in-memory only (the pre-existing behaviour), which is what
	// every test that does not care about persistence gets.
	notifyState *NotifyStateStore
	healthy     bool
	lastTick    time.Time

	// ── Self-observability (§10: no silent failures) ────────────────────────
	// The engine used to be structurally incapable of reporting its own
	// blindness: an eval error was indistinguishable from "the rule is not
	// firing", and `healthy` was set true at construction and never written
	// again. These fields make failure countable and health falsifiable.
	//
	// evalFailures/ruleEvalFailures are cumulative totals (read from outside the
	// package via EvalFailures/RuleEvalFailures so they can be exposed on
	// /metrics); degradedTicks drives the health verdict; lastGoodTick is the
	// last tick that evaluated cleanly; rulesLoadError records a rules-file that
	// failed to load (the engine is running with fewer rules than intended).
	evalFailures     uint64
	ruleEvalFailures map[string]uint64
	degradedTicks    int
	lastGoodTick     time.Time
	lastEvalError    string
	rulesLoadError   string
	lastEvalErrLog   map[string]time.Time // per-rule log rate limiter

	// Seams for tests: the rule evaluator (an HTTP call to VictoriaMetrics in
	// production) and the clock. Never nil — NewEngine sets the real ones.
	evalFn func(Rule) ([]Sample, error)
	now    func() time.Time
}

// unhealthyTickThreshold is how many CONSECUTIVE degraded ticks flip the engine
// unhealthy, and degradedRuleFraction is the share of the tick's rules that must
// error for that tick to count as degraded.
//
// The rule (documented because it is a judgement call): a tick is DEGRADED when
// at least HALF of the evaluated rules returned an error. A majority failure is
// a property of the metric store or of the whole rules file — not of one bad
// expression — so a single mistyped rule can never declare the engine down; it
// is reported through eval_failures / RuleEvalFailures() and a log line instead.
// Two consecutive degraded ticks (~60s at the 30s loop) rides out one transient
// VictoriaMetrics blip while still surfacing a real outage inside a minute. The
// first clean tick restores health immediately.
const (
	unhealthyTickThreshold = 2
	degradedRuleFraction   = 0.5
)

// evalErrLogEvery bounds per-rule eval-error logging. The loop runs every 30s
// and a broken rule fails on every tick, so an unfiltered log would emit two
// identical lines a minute forever and bury everything else. One line per rule
// per window keeps the failure visible; the counters carry the exact rate.
const evalErrLogEvery = 5 * time.Minute

func NewEngine(rulesFile string, n *notify.Dispatcher) *Engine {
	return &Engine{
		rulesFile:        rulesFile,
		active:           make(map[string]models.Alert),
		pending:          make(map[string]time.Time),
		dispatched:       make(map[string]bool),
		notifier:         n,
		healthy:          true,
		ruleEvalFailures: make(map[string]uint64),
		lastEvalErrLog:   make(map[string]time.Time),
		evalFn:           Evaluate,
		now:              time.Now,
	}
}

// SetNotifyState installs the durable notified set and RE-SEEDS the engine from
// it. Call it once, before Start.
//
// Three maps are restored, and all three matter:
//
//	active      so a still-firing alert is not seen as NEWLY firing (no re-page)
//	            — and so one that CLEARED while we were down is still resolved,
//	            exactly once, by the first tick after boot;
//	dispatched  so that resolution is actually delivered (a resolve is only sent
//	            when its fire was);
//	pending     from the alert's FiredAt, so the `for` clock is not restarted —
//	            otherwise a restored alert would be dropped from the next active
//	            set, spuriously RESOLVED, and re-fire one `for` later.
//
// Returns the number of alerts restored so the caller can say so in its boot
// log (§10: a restart that silently suppresses notifications is exactly the
// kind of invisible behaviour this file exists to replace).
func (e *Engine) SetNotifyState(s *NotifyStateStore) int {
	if s == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notifyState = s
	restored := 0
	for _, tenant := range s.Tenants() {
		for _, rec := range s.List(tenant) {
			a := rec.Alert
			if a.ID == "" {
				continue
			}
			e.active[a.ID] = a
			e.dispatched[a.ID] = true
			if !a.FiredAt.IsZero() {
				// The condition demonstrably held since FiredAt, so the `for`
				// gate is already satisfied; restarting the clock here would
				// resolve and re-fire the alert.
				e.pending[a.ID] = a.FiredAt
			}
			restored++
		}
	}
	return restored
}

// tenantOf derives an alert's owning tenant for the notified set. nil hook =
// platform-owned, never a guess from the alert's labels.
func (e *Engine) tenantOf(a models.Alert) string {
	if e.TenantOf == nil {
		return ""
	}
	return e.TenantOf(a)
}

// AddRule appends a rule and is safe to call at runtime (e.g. from the API).
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
}

// RemoveRule deletes every rule with the given name (names are expected to be
// unique) and reports whether anything was removed. Alerts the rule had active
// resolve naturally on the next evaluation tick.
func (e *Engine) RemoveRule(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	kept := e.rules[:0]
	removed := false
	for _, r := range e.rules {
		if r.Name == name {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	e.rules = kept
	return removed
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

func (e *Engine) Active() []models.Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]models.Alert, 0, len(e.active))
	for _, a := range e.active {
		out = append(out, a)
	}
	return out
}

// Start loads rules from disk (if a file is configured) and begins the
// evaluation loop. Cancelling ctx terminates evaluation.
func (e *Engine) Start(ctx context.Context) {
	_ = e.loadRulesFile() // best-effort: the error is logged + recorded in Health(), not fatal
	go e.loop(ctx)
}

// loadRulesFile loads the configured rules file into the engine.
//
// The load error used to be dropped on the floor (`if rules, err := LoadRules();
// err == nil { … }` with no else), so an unreadable or malformed RULES_FILE
// started the engine with ZERO rules and nothing anywhere said so — the platform
// reported "healthy, no alerts firing" while every shipped alert had silently
// ceased to exist. Now: the failure is logged loudly, recorded in Health()
// (`rules_load_error`) and pins healthy=false until the file is fixed and the
// engine restarted, while any rules that DID parse are still loaded — partial
// alerting beats none.
func (e *Engine) loadRulesFile() error {
	rules, err := LoadRules(e.rulesFile)
	e.mu.Lock()
	e.rules = append(e.rules, rules...)
	total := len(e.rules)
	if err != nil {
		e.rulesLoadError = err.Error()
		e.healthy = false
	} else {
		e.rulesLoadError = ""
	}
	e.mu.Unlock()
	if err != nil {
		log.Printf("alerts: rules file %q FAILED to load: %v — the engine is running with %d rule(s); every alert defined in that file is BLIND until it is fixed", e.rulesFile, err, total)
	}
	return err
}

func (e *Engine) loop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			e.evaluateAll()
			e.mu.Lock()
			e.lastTick = t.UTC()
			e.mu.Unlock()
		}
	}
}

func (e *Engine) evaluateAll() {
	rules := e.Rules()
	now := e.now().UTC()

	e.mu.RLock()
	prev := e.active
	prevPending := e.pending
	e.mu.RUnlock()

	// Prometheus-style `for` gating: a series that starts matching becomes
	// PENDING; it is promoted to active (dispatched) only once the condition
	// has held continuously for the rule's For. A series that stops matching
	// drops out of pending, so an intermittent condition restarts its clock.
	// Resolution is tick-grained (the engine evaluates every 30s).
	next := make(map[string]models.Alert)
	nextPending := make(map[string]time.Time)
	failed := 0
	lastErrText := ""
	for _, r := range rules {
		samples, err := e.evalFn(r)
		if err != nil {
			// §10: an eval ERROR is not "the rule is not firing". This branch
			// used to share `continue` with the empty-result branch, so a
			// VictoriaMetrics outage emptied the freshly-rebuilt active set and
			// the resolution leg below RESOLVED every live alert — closing the
			// PagerDuty incidents it had opened — then re-paged on recovery.
			// Carry this rule's alerts (and their pending clocks) forward
			// untouched: an unknown state must never be published as "clear".
			failed++
			lastErrText = fmt.Sprintf("rule %q: %v", r.Name, err)
			e.noteEvalFailure(r.Name, err, now)
			for id, a := range prev {
				if ruleOwnsID(r.Name, id) {
					next[id] = a
				}
			}
			for id, held := range prevPending {
				if ruleOwnsID(r.Name, id) {
					nextPending[id] = held
				}
			}
			continue
		}
		if len(samples) == 0 {
			continue // genuinely evaluated and not firing — resolve normally
		}
		for _, s := range samples {
			labels := mergeLabels(r.Labels, s.Labels)
			sev := r.Severity
			if sev == "" {
				sev = labels["severity"]
			}
			id := r.Name
			if fp := fingerprint(s.Labels); fp != "" {
				id = r.Name + "|" + fp
			}
			heldSince, wasPending := prevPending[id]
			if !wasPending {
				heldSince = now
			}
			nextPending[id] = heldSince
			if now.Sub(heldSince) < r.For {
				continue // still pending — not active yet
			}
			firedAt := now
			if p, ok := prev[id]; ok { // preserve the original fire time
				firedAt = p.FiredAt
			}
			next[id] = models.Alert{
				ID:       id,
				Rule:     r.Name,
				Severity: sev,
				Summary:  renderSummary(r.Annotations["summary"], s.Labels, s.Value),
				Labels:   labels,
				DeviceID: s.Labels["device"],
				FiredAt:  firedAt,
			}
		}
	}

	// Swap in the freshly-computed active set (this also resolves alerts whose
	// series stopped firing), then dispatch only the newly-firing ones.
	// The same critical section records the tick's health verdict — see
	// unhealthyTickThreshold for the rule and why it is drawn there.
	e.mu.Lock()
	e.active = next
	e.pending = nextPending
	degraded := failed > 0 && float64(failed) >= degradedRuleFraction*float64(len(rules))
	if degraded {
		e.degradedTicks++
	} else {
		e.degradedTicks = 0
		e.lastGoodTick = now
	}
	e.lastEvalError = lastErrText
	was := e.healthy
	e.healthy = e.rulesLoadError == "" && e.degradedTicks < unhealthyTickThreshold
	became := e.healthy
	degradedTicks := e.degradedTicks
	e.mu.Unlock()
	// Log the TRANSITION, not the state: the loop ticks twice a minute forever.
	switch {
	case was && !became:
		log.Printf("alerts: engine UNHEALTHY — %d of %d rules failed to evaluate for %d consecutive tick(s) (last: %s); active alerts are being HELD, not resolved", failed, len(rules), degradedTicks, lastErrText)
	case !was && became:
		log.Printf("alerts: engine recovered — all %d rules evaluated cleanly", len(rules))
	}
	for id, a := range next {
		if _, existed := prev[id]; existed {
			continue
		}
		// Fold the transition into episodes FIRST, so the suppression check sees
		// the current episode state (a re-fire folding into a muted episode is
		// suppressed; a fresh episode after a close never inherits a mute).
		if e.OnTransition != nil {
			e.OnTransition(a, true)
		}
		suppressed := e.SuppressNotify != nil && e.SuppressNotify(a)
		if !suppressed && e.notifier != nil {
			e.notifier.Dispatch(a)
		}
		if !suppressed {
			e.mu.Lock()
			e.dispatched[id] = true
			e.mu.Unlock()
			// DURABLE half: survive the restart that used to re-page this.
			// A SUPPRESSED firing is deliberately not recorded — nothing went
			// out, so nothing must be suppressed after a restart either.
			e.notifyState.MarkNotified(e.tenantOf(a), a)
		}
		if e.OnFire != nil {
			e.OnFire(a) // incident ingest is not a notification — never suppressed
		}
	}
	// Refresh the still-firing records so a chronic alert does not age out of
	// the notified set and re-page itself. Touch is rate-limited internally, so
	// this is a map read per active alert per tick and a write once an hour.
	if e.notifyState != nil {
		for id, a := range next {
			if _, existed := prev[id]; existed {
				e.notifyState.Touch(e.tenantOf(a), id)
			}
		}
	}
	// Resolution leg: an alert that WAS active and no longer fires has cleared —
	// tell resolution-capable channels (PagerDuty closes the incident it opened
	// under the same dedup key), but only when the fire notification actually went
	// out. Resolution is tick-grained like everything else.
	for id, a := range prev {
		if _, still := next[id]; still {
			continue
		}
		if e.OnTransition != nil {
			e.OnTransition(a, false)
		}
		e.mu.Lock()
		wasDispatched := e.dispatched[id]
		delete(e.dispatched, id)
		e.mu.Unlock()
		if wasDispatched && e.notifier != nil {
			e.notifier.DispatchResolve(a)
		}
		// The alert cleared: forget it, so its NEXT firing notifies again.
		// Unconditional — a record with no live `dispatched` entry (restored,
		// then resolved) must be cleared too, or it would suppress forever.
		e.notifyState.Clear(e.tenantOf(a), id)
	}
	// ONE blob write per tick, not one per alert: the whole-collection write is
	// O(N), so per-record flushing would be O(N²) under a storm (§9).
	if err := e.notifyState.Flush(); err != nil {
		log.Printf("alerts: could not persist the notified-alert state: %v — alerting continues, but a restart may re-notify still-firing alerts", err)
	}
}

// ruleOwnsID reports whether an active-alert / pending id belongs to the named
// rule. Ids are "<rule>" or "<rule>|<fingerprint>" (see evaluateAll).
func ruleOwnsID(rule, id string) bool {
	return id == rule || strings.HasPrefix(id, rule+"|")
}

// noteEvalFailure counts one rule's failed evaluation and logs it at most once
// per evalErrLogEvery per rule. Counting is what makes a SINGLE broken rule
// expression visible: it is a minority failure, so it never trips the health
// flag, and before this it produced no signal of any kind — forever.
func (e *Engine) noteEvalFailure(rule string, err error, now time.Time) {
	e.mu.Lock()
	e.evalFailures++
	if e.ruleEvalFailures == nil {
		e.ruleEvalFailures = make(map[string]uint64)
	}
	e.ruleEvalFailures[rule]++
	total := e.ruleEvalFailures[rule]
	if e.lastEvalErrLog == nil {
		e.lastEvalErrLog = make(map[string]time.Time)
	}
	last, seen := e.lastEvalErrLog[rule]
	shouldLog := !seen || now.Sub(last) >= evalErrLogEvery
	if shouldLog {
		e.lastEvalErrLog[rule] = now
	}
	e.mu.Unlock()
	if shouldLog {
		log.Printf("alerts: rule %q FAILED to evaluate (%d failure(s) so far): %v — its alerts are HELD (not resolved) and the rule is blind until it succeeds", rule, total, err)
	}
}

// EvalFailures reports the cumulative number of rule evaluations that errored.
// Exported so the API can publish it on /metrics — the defect being fixed is
// that this condition had no counter, no log and no health effect at all.
func (e *Engine) EvalFailures() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.evalFailures
}

// RuleEvalFailures returns a copy of the per-rule eval-failure counts, so one
// permanently broken rule expression can be named rather than merely summed.
func (e *Engine) RuleEvalFailures() map[string]uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]uint64, len(e.ruleEvalFailures))
	for k, v := range e.ruleEvalFailures {
		out[k] = v
	}
	return out
}

// LastSuccessfulTick reports when evaluation last completed without a degraded
// verdict (zero if it never has).
func (e *Engine) LastSuccessfulTick() time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastGoodTick
}

// mergeLabels overlays metric labels onto the rule's labels (severity, etc.),
// dropping the internal __name__.
func mergeLabels(ruleLabels, metric map[string]string) map[string]string {
	out := make(map[string]string, len(ruleLabels)+len(metric))
	for k, v := range ruleLabels {
		out[k] = v
	}
	for k, v := range metric {
		if k != "__name__" {
			out[k] = v
		}
	}
	return out
}

// fingerprint is a stable per-series key from the metric labels.
func fingerprint(metric map[string]string) string {
	keys := make([]string, 0, len(metric))
	for k := range metric {
		if k != "__name__" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+metric[k])
	}
	return strings.Join(parts, ",")
}

var (
	tmplLabel = regexp.MustCompile(`\{\{\s*\$labels\.([A-Za-z0-9_]+)\s*\}\}`)
	tmplValue = regexp.MustCompile(`\{\{[^}]*\$value[^}]*\}\}`)
	tmplAny   = regexp.MustCompile(`\{\{[^}]*\}\}`)
)

// renderSummary expands a Prometheus-style annotation template against a firing
// series' labels and value, so the UI shows "High CPU on leaf1 (arista): 92%"
// instead of raw {{ $labels.device }} placeholders.
func renderSummary(tmpl string, labels map[string]string, value float64) string {
	if tmpl == "" {
		return tmpl
	}
	s := tmplLabel.ReplaceAllStringFunc(tmpl, func(m string) string {
		if sub := tmplLabel.FindStringSubmatch(m); sub != nil {
			if v, ok := labels[sub[1]]; ok {
				return v
			}
		}
		return "?"
	})
	s = tmplValue.ReplaceAllString(s, fmt.Sprintf("%g", value))
	s = tmplAny.ReplaceAllString(s, "") // strip any leftover templating
	return strings.TrimSpace(s)
}

func (e *Engine) Health() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]any{
		"healthy":   e.healthy,
		"rules":     len(e.rules),
		"active":    len(e.active),
		"last_tick": e.lastTick,
		// Why the engine believes what it believes — a "healthy" with no
		// evidence behind it is what made this subsystem unfalsifiable.
		"last_successful_tick": e.lastGoodTick,
		"eval_failures":        e.evalFailures,
		"degraded_ticks":       e.degradedTicks,
		"last_eval_error":      e.lastEvalError,
		"rules_load_error":     e.rulesLoadError,
	}
}

// LoadRules parses a minimal subset of the Prometheus rules-file format:
//
//	groups:
//	  - name: foo
//	    rules:
//	      - alert: HighCPU
//	        expr: cpu_usage > 90
//	        for: 5m
//	        labels: { severity: warning }
//	        annotations:
//	          summary: "..."
//
// Implementation is a hand-rolled scanner so the package stays stdlib-only.
// Swap for `gopkg.in/yaml.v3` once we need fuller YAML semantics.
func LoadRules(path string) ([]Rule, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil // OK — rules can be added later via API.
		}
		return nil, err
	}
	return parseRulesYAML(string(b))
}

// yamlRuleKeys are the keys the parser understands; a folded-expr continuation
// ends at the first line that is one of these (or a dedent).
var yamlRuleKeys = []string{"- alert:", "alert:", "expr:", "for:", "labels:", "annotations:", "severity:", "summary:"}

func isYAMLRuleKey(trim string) bool {
	for _, k := range yamlRuleKeys {
		if strings.HasPrefix(trim, k) {
			return true
		}
	}
	return false
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// validateParsedRule rejects a rule the engine could never evaluate.
//
// The parser used to admit ANY `- alert:` block it saw and return a nil error
// always: a rule that lost its `expr:` (a bad indent, a dropped line, a folded
// scalar with no continuation) was counted as loaded, shown in the rules list,
// and then failed on every 30s tick forever with nothing said. A rule the
// engine cannot evaluate is a defect in the file, and the file must say so at
// LOAD time, naming the rule.
func validateParsedRule(r Rule) error {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return fmt.Errorf("rule with no alert name (expr %q)", strings.TrimSpace(r.Expr))
	}
	switch expr := strings.TrimSpace(r.Expr); expr {
	case "":
		return fmt.Errorf("rule %q has no expr — it can never evaluate", name)
	case ">", "|", ">-", "|-":
		return fmt.Errorf("rule %q kept the YAML fold marker %q as its expr — the folded block is empty", name, expr)
	}
	return nil
}

// parseRulesYAML returns the rules it could parse plus an error naming every
// rule it REJECTED. Both are meaningful: the caller loads the good rules and
// reports the bad ones (see Engine.loadRulesFile).
func parseRulesYAML(s string) ([]Rule, error) {
	var rules []Rule
	var rejected []string
	var cur *Rule
	flush := func() {
		if cur == nil {
			return
		}
		if err := validateParsedRule(*cur); err != nil {
			rejected = append(rejected, err.Error())
			cur = nil
			return
		}
		rules = append(rules, *cur)
		cur = nil
	}

	// Folded/literal expr blocks (`expr: >` / `expr: |`): promtool-valid and
	// common for long PromQL. #101 fix: the line parser used to keep the bare
	// fold marker as the expression (Expr == ">") and silently drop the actual
	// query — the rule then errored on every evaluation tick. Continuation
	// lines (more indented, not a known key) are joined with spaces.
	exprCont := false
	exprIndent := 0

	for _, raw := range strings.Split(s, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if exprCont {
			if cur != nil && indentOf(line) > exprIndent && !isYAMLRuleKey(trim) {
				cur.Expr = strings.TrimSpace(cur.Expr + " " + trim)
				continue
			}
			exprCont = false
		}
		switch {
		case strings.HasPrefix(trim, "- alert:"):
			flush()
			cur = &Rule{Name: strings.TrimSpace(strings.TrimPrefix(trim, "- alert:"))}
		case cur != nil && strings.HasPrefix(trim, "alert:"):
			cur.Name = strings.TrimSpace(strings.TrimPrefix(trim, "alert:"))
		case cur != nil && strings.HasPrefix(trim, "expr:"):
			v := strings.TrimSpace(strings.TrimPrefix(trim, "expr:"))
			switch v {
			case ">", "|", ">-", "|-", "":
				cur.Expr = ""
				exprCont = true
				exprIndent = indentOf(line)
			default:
				cur.Expr = v
			}
		case cur != nil && strings.HasPrefix(trim, "for:"):
			if d, err := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(trim, "for:"))); err == nil {
				cur.For = d
			}
		case cur != nil && strings.HasPrefix(trim, "labels:"):
			// Inline flow map: `labels: { severity: critical, layer: stack }`.
			// Block-style labels keep flowing through the `severity:` case below.
			rest := strings.TrimSpace(strings.TrimPrefix(trim, "labels:"))
			if strings.HasPrefix(rest, "{") && strings.HasSuffix(rest, "}") {
				if cur.Labels == nil {
					cur.Labels = map[string]string{}
				}
				for _, kv := range strings.Split(rest[1:len(rest)-1], ",") {
					k, v, ok := strings.Cut(kv, ":")
					if !ok {
						continue
					}
					cur.Labels[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
				}
			}
		case cur != nil && strings.HasPrefix(trim, "severity:"):
			if cur.Labels == nil {
				cur.Labels = map[string]string{}
			}
			cur.Labels["severity"] = strings.TrimSpace(strings.TrimPrefix(trim, "severity:"))
		case cur != nil && strings.HasPrefix(trim, "summary:"):
			if cur.Annotations == nil {
				cur.Annotations = map[string]string{}
			}
			cur.Annotations["summary"] = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "summary:")))
		}
	}
	flush()
	if len(rejected) > 0 {
		return rules, fmt.Errorf("%d malformed rule(s) rejected (%d loaded): %s",
			len(rejected), len(rules), strings.Join(rejected, "; "))
	}
	return rules, nil
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
