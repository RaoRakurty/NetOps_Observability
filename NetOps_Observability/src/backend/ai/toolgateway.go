// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// toolgateway.go — the ONE way a tool runs (tracker 337 N-A8). Toolbox.Invoke
// applies a tool's contract (toolcontract.go) on every path — the grounded
// engine's problem and module paths, the skill chain, and the copilot agent
// loop:
//
//	authorize (policy, gate 2) → args are bounded strings → per-tenant rate →
//	run under the contract's timeout → output fits the schema → measured
//
// A timeout holds even when a data source ignores its context: the tool runs
// in its own goroutine and Invoke returns at the deadline (the goroutine is
// abandoned to its context, never waited on). A result that does not fit its
// schema is dropped — the caller gets an empty Result and the outcome says why.

// Gateway outcomes beyond the policy ones (ok, not_registered, policy_denied)
// and the tool's own error reasons (toolErrReason).
const (
	OutcomeOK             = "ok"
	OutcomeNotRegistered  = "not_registered"
	OutcomePolicyDenied   = "policy_denied"
	OutcomeRateLimited    = "rate_limited"
	OutcomeBadArgs        = "bad_args"
	OutcomeTimeout        = "timeout"
	OutcomeCancelled      = "cancelled"
	OutcomeSchemaRejected = "schema_rejected"
)

// Argument bounds at the gateway. The tool still validates its own arguments.
const (
	maxToolArgs     = 16
	maxToolArgChars = 512
)

// ToolLimiter is a per-key fixed-window limiter: AllowN reports whether one
// more call fits under perMin calls per minute for key.
type ToolLimiter interface {
	AllowN(key string, perMin int) bool
}

// ToolGateway holds what outlives one request: the limiter (a budget spans
// requests) and the metrics. Process-lived; one per server.
type ToolGateway struct {
	Limiter ToolLimiter
	Metrics *ToolMetrics
}

// NewToolGateway returns a gateway with the in-package limiter and metrics.
func NewToolGateway() *ToolGateway {
	return &ToolGateway{Limiter: newWindowLimiter(time.Now), Metrics: NewToolMetrics()}
}

// Invocation is what one call produced. Result is empty unless Outcome is ok.
type Invocation struct {
	Tool       AITool // nil when not registered
	Decision   Decision
	Registered bool
	Result     ToolResult
	Outcome    string
	Err        error
	Elapsed    time.Duration
	Truncated  bool
	// RejectedSHA256 is the hash of a result dropped for its schema — proof
	// of what was refused without keeping it.
	RejectedSHA256 string
}

// OK reports a call that ran and returned a usable result.
func (iv Invocation) OK() bool { return iv.Outcome == OutcomeOK }

// Invoke runs one tool under its contract. It never panics on a missing
// gateway: the Toolbox built by Orchestrator.Toolbox always carries one.
func (b Toolbox) Invoke(ctx context.Context, p Principal, name string, args ToolArgs) Invocation {
	iv := Invocation{}
	// Progress (N-E2): a start for every call, so every finish has one —
	// including denied and not-wired steps. The tool NAME only.
	emitTrace(b.Trace, TraceEvent{Type: TraceToolStarted, Tool: name})
	tool, d, registered := b.Authorize(name, p)
	iv.Tool, iv.Decision, iv.Registered = tool, d, registered
	gw := b.Gateway
	if gw == nil {
		gw = NewToolGateway()
	}
	finish := func(outcome string) Invocation {
		iv.Outcome = outcome
		gw.Metrics.observe(name, outcome)
		emitTrace(b.Trace, TraceEvent{Type: TraceToolFinished, Tool: name, Outcome: traceOutcome(outcome)})
		return iv
	}
	if !registered {
		return finish(OutcomeNotRegistered)
	}
	if !d.Allow {
		return finish(OutcomePolicyDenied)
	}
	c, ok := toolContracts[name]
	if !ok { // registration guarantees a contract; belt and braces
		return finish(OutcomePolicyDenied)
	}
	if err := validToolArgs(args); err != nil {
		iv.Err = err
		return finish(OutcomeBadArgs)
	}
	if !gw.Limiter.AllowN(p.Tenant+"\x1f"+name, c.RatePerMin) {
		iv.Err = fmt.Errorf("%s: rate limit of %d per minute reached for this workspace", name, c.RatePerMin)
		return finish(OutcomeRateLimited)
	}

	cctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	type ran struct {
		res ToolResult
		err error
	}
	done := make(chan ran, 1)
	started := time.Now()
	go func() {
		res, err := tool.Run(cctx, p, args)
		done <- ran{res, err}
	}()
	var r ran
	cutOff := false
	select {
	case r = <-done:
	case <-cctx.Done():
		cutOff = true // nothing came back before the deadline, or the caller left
	}
	iv.Elapsed = time.Since(started)
	if cutOff {
		if ctx.Err() != nil {
			iv.Err = ctx.Err()
			return finish(OutcomeCancelled)
		}
		iv.Err = fmt.Errorf("%s did not answer within %s", name, c.Timeout)
		return finish(OutcomeTimeout)
	}
	if r.err != nil {
		iv.Err = r.err
		if errors.Is(r.err, context.DeadlineExceeded) && ctx.Err() == nil {
			return finish(OutcomeTimeout)
		}
		if errors.Is(r.err, context.Canceled) && ctx.Err() != nil {
			return finish(OutcomeCancelled)
		}
		return finish(toolErrReason(r.err))
	}
	if err := c.Output.Validate(r.res); err != nil {
		iv.Err = err
		iv.RejectedSHA256 = HashToolResult(r.res)
		return finish(OutcomeSchemaRejected)
	}
	iv.Result, iv.Truncated = r.res, r.res.Truncated
	return finish(OutcomeOK)
}

// validToolArgs: a bounded number of bounded, control-free string values.
func validToolArgs(args ToolArgs) error {
	if len(args) > maxToolArgs {
		return fmt.Errorf("%d arguments (max %d)", len(args), maxToolArgs)
	}
	for k, v := range args {
		if k == "" || !utf8.ValidString(k) || !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxToolArgChars {
			return fmt.Errorf("argument %q is not a bounded string", k)
		}
		for _, r := range k + v {
			if unicode.IsControl(r) {
				return fmt.Errorf("argument %q contains a control character", k)
			}
		}
	}
	return nil
}

// ── limiter ────────────────────────────────────────────────────────────────

// windowLimiter is a fixed one-minute window per key, swept as windows roll
// over so its memory is bounded by the keys active in the last minute.
type windowLimiter struct {
	mu    sync.Mutex
	now   func() time.Time
	start time.Time
	n     map[string]int
}

func newWindowLimiter(now func() time.Time) *windowLimiter {
	return &windowLimiter{now: now, start: now(), n: map[string]int{}}
}

func (l *windowLimiter) AllowN(key string, perMin int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t := l.now(); t.Sub(l.start) >= time.Minute {
		l.start, l.n = t, map[string]int{}
	}
	if l.n[key] >= perMin {
		return false
	}
	l.n[key]++
	return true
}

// ── metrics ────────────────────────────────────────────────────────────────

// ToolMetrics counts calls per tool and outcome. No tenant label: the tool
// set is closed (the contract table), the tenant set is not.
type ToolMetrics struct {
	mu sync.Mutex
	n  map[[2]string]uint64
}

func NewToolMetrics() *ToolMetrics { return &ToolMetrics{n: map[[2]string]uint64{}} }

func (m *ToolMetrics) observe(tool, outcome string) {
	if m == nil {
		return
	}
	if _, known := toolContracts[tool]; !known {
		tool = "unknown" // never a model-chosen string as a label
	}
	m.mu.Lock()
	m.n[[2]string{tool, outcome}]++
	m.mu.Unlock()
}

// Count returns one counter (tests and the metrics writer).
func (m *ToolMetrics) Count(tool, outcome string) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n[[2]string{tool, outcome}]
}

// Write renders Prometheus text:
//
//	netops_ai_tool_invocations_total{tool,outcome}
//	netops_ai_tool_timeouts_total{tool}
//	netops_ai_tool_rate_limited_total{tool}
//	netops_ai_tool_schema_rejects_total{tool}
func (m *ToolMetrics) Write(w io.Writer) error {
	m.mu.Lock()
	keys := make([][2]string, 0, len(m.n))
	for k := range m.n {
		keys = append(keys, k)
	}
	vals := make(map[[2]string]uint64, len(m.n))
	for k, v := range m.n {
		vals[k] = v
	}
	m.mu.Unlock()
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var b strings.Builder
	b.WriteString("# HELP netops_ai_tool_invocations_total Iris tool calls by tool and outcome (N-A8 gateway).\n# TYPE netops_ai_tool_invocations_total counter\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "netops_ai_tool_invocations_total{tool=%q,outcome=%q} %d\n", k[0], k[1], vals[k])
	}
	for _, spec := range []struct{ name, outcome, help string }{
		{"netops_ai_tool_timeouts_total", OutcomeTimeout, "Iris tool calls cut off at their contract timeout."},
		{"netops_ai_tool_rate_limited_total", OutcomeRateLimited, "Iris tool calls refused by the per-tenant tool rate."},
		{"netops_ai_tool_schema_rejects_total", OutcomeSchemaRejected, "Iris tool results dropped for not fitting their output schema."},
	} {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", spec.name, spec.help, spec.name)
		for _, k := range keys {
			if k[1] == spec.outcome {
				fmt.Fprintf(&b, "%s{tool=%q} %d\n", spec.name, k[0], vals[k])
			}
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
