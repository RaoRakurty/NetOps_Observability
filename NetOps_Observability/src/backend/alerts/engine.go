// Package alerts hosts the rule-driven alert evaluator and the state
// machine that decides when alerts fire, deduplicate, and resolve.
package alerts

import (
	"context"
	"errors"
	"io/fs"
	"os"
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

// Engine periodically evaluates every rule against the metric store.
type Engine struct {
	mu        sync.RWMutex
	rules     []Rule
	active    map[string]models.Alert
	rulesFile string
	notifier  *notify.Dispatcher
	healthy   bool
	lastTick  time.Time
}

func NewEngine(rulesFile string, n *notify.Dispatcher) *Engine {
	return &Engine{
		rulesFile: rulesFile,
		active:    make(map[string]models.Alert),
		notifier:  n,
		healthy:   true,
	}
}

// AddRule appends a rule and is safe to call at runtime (e.g. from the API).
func (e *Engine) AddRule(r Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, r)
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
	for _, r := range rules {
		fired, err := Evaluate(r)
		if err != nil || !fired {
			continue
		}
		alert := models.Alert{
			ID:       r.Name,
			Rule:     r.Name,
			Severity: r.Severity,
			Summary:  r.Annotations["summary"],
			Labels:   r.Labels,
			FiredAt:  time.Now().UTC(),
		}
		e.mu.Lock()
		_, already := e.active[alert.ID]
		e.active[alert.ID] = alert
		e.mu.Unlock()
		if !already && e.notifier != nil {
			e.notifier.Dispatch(alert)
		}
	}
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
//   groups:
//     - name: foo
//       rules:
//         - alert: HighCPU
//           expr: cpu_usage > 90
//           for: 5m
//           labels: { severity: warning }
//           annotations:
//             summary: "..."
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

func parseRulesYAML(s string) ([]Rule, error) {
	var rules []Rule
	var cur *Rule
	flush := func() {
		if cur != nil {
			rules = append(rules, *cur)
			cur = nil
		}
	}

	for _, raw := range strings.Split(s, "\n") {
		line := raw
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trim, "- alert:"):
			flush()
			cur = &Rule{Name: strings.TrimSpace(strings.TrimPrefix(trim, "- alert:"))}
		case cur != nil && strings.HasPrefix(trim, "alert:"):
			cur.Name = strings.TrimSpace(strings.TrimPrefix(trim, "alert:"))
		case cur != nil && strings.HasPrefix(trim, "expr:"):
			cur.Expr = strings.TrimSpace(strings.TrimPrefix(trim, "expr:"))
		case cur != nil && strings.HasPrefix(trim, "for:"):
			if d, err := time.ParseDuration(strings.TrimSpace(strings.TrimPrefix(trim, "for:"))); err == nil {
				cur.For = d
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
