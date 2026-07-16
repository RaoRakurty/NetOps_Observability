// Package alerts hosts the rule-driven alert evaluator and the state
// machine that decides when alerts fire, deduplicate, and resolve.
package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
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
	healthy    bool
	lastTick   time.Time

	// Seams for tests: the rule evaluator (an HTTP call to VictoriaMetrics in
	// production) and the clock. Never nil — NewEngine sets the real ones.
	evalFn func(Rule) ([]Sample, error)
	now    func() time.Time
}

func NewEngine(rulesFile string, n *notify.Dispatcher) *Engine {
	return &Engine{
		rulesFile:  rulesFile,
		active:     make(map[string]models.Alert),
		pending:    make(map[string]time.Time),
		dispatched: make(map[string]bool),
		notifier:   n,
		healthy:    true,
		evalFn:     Evaluate,
		now:        time.Now,
	}
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
	if rules, err := LoadRules(e.rulesFile); err == nil {
		e.mu.Lock()
		e.rules = append(e.rules, rules...)
		e.mu.Unlock()
	}
	go e.loop(ctx)
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
	for _, r := range rules {
		samples, err := e.evalFn(r)
		if err != nil || len(samples) == 0 {
			continue
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
	e.mu.Lock()
	e.active = next
	e.pending = nextPending
	e.mu.Unlock()
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
		}
		if e.OnFire != nil {
			e.OnFire(a) // incident ingest is not a notification — never suppressed
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
	}
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

func parseRulesYAML(s string) ([]Rule, error) {
	var rules []Rule
	var cur *Rule
	flush := func() {
		if cur != nil {
			rules = append(rules, *cur)
			cur = nil
		}
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
