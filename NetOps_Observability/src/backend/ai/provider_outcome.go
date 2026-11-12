// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// provider_outcome.go — what happened to one model-provider call, in a closed
// vocabulary (tracker 337, Iris latency batch 2026-11-10).
//
// The 2026-11-10 lab measurement found two provider calls that failed with no
// log line naming the provider, the model or the reason, while the operator
// waited 20 s and then 62 s for answers whose evidence was ready in 56 ms. Three
// things follow, and they live here so every caller shares them:
//
//   - ClassifyProviderError maps any provider error onto a closed outcome class
//     (timeout, auth, model_not_found, rate_limited, …) that is safe to log and
//     to use as a metric label — never the provider's raw text (SR-022);
//   - the per-stage model budget (StageBudgets): a model narrates a READY
//     deterministic answer only inside a short deadline, so a slow or dead
//     provider can never hold an answer hostage (CLAUDE.md §9: all IO bounded);
//   - FallbackNoteFor turns the outcome into the one honest footer line the
//     operator sees ("Model narrative timed out; showing the evidence answer.").

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/applog"
)

// Provider outcome classes. Closed set: metric labels and log fields only ever
// carry one of these.
const (
	ProvOK            = "ok"
	ProvTimeout       = "timeout"         // the stage budget or the HTTP client deadline ran out
	ProvCanceled      = "canceled"        // the caller left; not the provider's fault
	ProvAuth          = "auth"            // 401/403: key rejected or not allowed
	ProvModelNotFound = "model_not_found" // 404: the model name does not exist for this key
	ProvBadRequest    = "bad_request"     // other 4xx: the request shape was refused
	ProvRateLimited   = "rate_limited"    // 429: quota or rate limit
	ProvServer        = "server_error"    // 5xx / 529
	ProvEmpty         = "empty_response"  // 2xx with no usable text (blocked, or the output cap spent on thinking)
	ProvNetwork       = "network"         // connect/DNS/TLS/reset
	ProvBreakerOpen   = "breaker_open"    // skipped: recent consecutive failures
	ProvBudget        = "budget_exhausted"
	ProvNoProvider    = "no_provider"
	ProvError         = "error" // anything else (decode failure, …)
)

// ProviderOutcomes is every class, for metric pre-registration and tests.
var ProviderOutcomes = []string{ProvOK, ProvTimeout, ProvCanceled, ProvAuth, ProvModelNotFound,
	ProvBadRequest, ProvRateLimited, ProvServer, ProvEmpty, ProvNetwork, ProvBreakerOpen,
	ProvBudget, ProvNoProvider, ProvError}

// ErrBudgetExhausted is the refusal once a tenant's daily token budget is spent.
var ErrBudgetExhausted = errors.New("daily AI token budget exhausted for this workspace")

// ErrProviderBreakerOpen means every provider this caller may use failed
// repeatedly in a row and is cooling down; no call was made.
var ErrProviderBreakerOpen = errors.New("AI provider paused after repeated failures")

// ProviderEmptyError is a 2xx provider answer that carried no usable text. The
// reasons are the provider's own closed enums (finish/block reason), safe to log.
type ProviderEmptyError struct {
	Provider     string
	FinishReason string // e.g. Gemini MAX_TOKENS / SAFETY, OpenAI length / content_filter
	BlockReason  string // Gemini promptFeedback.blockReason
	ThoughtTok   int64  // Gemini thoughtsTokenCount — thinking that spent the output cap
}

func (e *ProviderEmptyError) Error() string {
	var b strings.Builder
	b.WriteString(e.Provider)
	b.WriteString(": empty response")
	if e.FinishReason != "" {
		b.WriteString(" (finish ")
		b.WriteString(e.FinishReason)
		b.WriteString(")")
	}
	if e.BlockReason != "" {
		b.WriteString(" (blocked ")
		b.WriteString(e.BlockReason)
		b.WriteString(")")
	}
	return b.String()
}

// ClassifyProviderError maps a provider-call error onto an outcome class.
// nil is ProvOK.
func ClassifyProviderError(err error) string {
	if err == nil {
		return ProvOK
	}
	var se *ProviderStatusError
	var ee *ProviderEmptyError
	switch {
	case errors.Is(err, ErrProviderBreakerOpen):
		return ProvBreakerOpen
	case errors.Is(err, ErrBudgetExhausted):
		return ProvBudget
	case errors.Is(err, ErrNoProvider):
		return ProvNoProvider
	case errors.As(err, &se):
		return classifyStatus(se.Status, se.Reason)
	case errors.As(err, &ee):
		return ProvEmpty
	case errors.Is(err, context.DeadlineExceeded):
		return ProvTimeout
	case errors.Is(err, context.Canceled):
		return ProvCanceled
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return ProvTimeout
	}
	var ne net.Error
	var oe *net.OpError
	var de *net.DNSError
	if errors.As(err, &oe) || errors.As(err, &de) || errors.As(err, &ne) {
		return ProvNetwork
	}
	return ProvError
}

func classifyStatus(code int, reason string) string {
	switch {
	// Gemini answers a bad key with 400 INVALID_ARGUMENT + ErrorInfo reason
	// API_KEY_INVALID, not 401 — it is still the key that is wrong.
	case code == http.StatusUnauthorized || code == http.StatusForbidden || reason == "API_KEY_INVALID":
		return ProvAuth
	case code == http.StatusNotFound:
		return ProvModelNotFound
	case code == http.StatusTooManyRequests:
		return ProvRateLimited
	case code == http.StatusRequestTimeout || code == http.StatusGatewayTimeout:
		return ProvTimeout
	case code >= 500:
		return ProvServer
	case code >= 400:
		return ProvBadRequest
	}
	return ProvError
}

// ProviderStatusOf returns the HTTP status a provider answered with, 0 when the
// error is not a status error.
func ProviderStatusOf(err error) int {
	var se *ProviderStatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return 0
}

// CountsAgainstProvider reports whether an outcome is the PROVIDER failing (and
// so feeds the circuit breaker). A caller that left, a spent budget, a skipped
// call and "nothing configured" are not the provider's failures.
func CountsAgainstProvider(outcome string) bool {
	switch outcome {
	case ProvOK, ProvCanceled, ProvBreakerOpen, ProvBudget, ProvNoProvider:
		return false
	}
	return true
}

// ── per-stage model budget ──────────────────────────────────────────────────

// Default per-stage budgets. A narration over an answer that is already
// complete gets this long; then the answer ships without it. The fast tier
// writes a headline; the strong tier a multi-fact narrative.
const (
	DefaultFastBudget   = 8 * time.Second
	DefaultStrongBudget = 15 * time.Second
	MaxStageBudget      = 60 * time.Second // a configured value is clamped here (the HTTP client's own ceiling)
)

// StageBudgets bounds one model call by tier. The zero value means the
// defaults — the guarantee is on unless a value is set, never off by omission.
type StageBudgets struct {
	Fast   time.Duration
	Strong time.Duration
}

// For returns the budget for a tier: Fast for the fast tier, Strong for the
// strong tier and the untiered call.
func (b StageBudgets) For(tier ModelTier) time.Duration {
	d := b.Strong
	def := DefaultStrongBudget
	if tier == TierFast {
		d, def = b.Fast, DefaultFastBudget
	}
	if d <= 0 {
		d = def
	}
	if d > MaxStageBudget {
		d = MaxStageBudget
	}
	return d
}

// ModelCallContext bounds ONE model call by its own stage budget, detached from
// the caller's CANCELLATION but not from the caller's DEADLINE.
//
// Found live 2026-11-10 15:33Z: the operator's browser reloaded the page while
// a skill answer was narrating; the request context was cancelled, and the
// Gemini call died 0.35 s in with "context canceled" — the answer was ledgered
// as evidence-only and nothing said why. A narration is a bounded, budgeted
// unit of work: it now runs to its own budget (8 s fast / 15 s strong) or to an
// earlier deadline the caller set (a skill turn's 45 s, a tie-break's 5 s),
// whichever comes first, and a cancelled caller is logged (noteCallerLeft), not
// silent. The cost of finishing is bounded by the stage budget and metered by
// the tenant's daily token budget like any other call. Context VALUES (the
// decision ledger, the model note) are kept.
func ModelCallContext(parent context.Context, budget time.Duration) (context.Context, context.CancelFunc) {
	dl := time.Now().Add(budget)
	if pd, ok := parent.Deadline(); ok && pd.Before(dl) {
		dl = pd
	}
	return context.WithDeadline(context.WithoutCancel(parent), dl)
}

// noteCallerLeft logs a model call whose caller was cancelled while it ran:
// the call itself completed under its own budget (ModelCallContext), and the
// answer may never reach the operator — which an operator-facing log must say.
func noteCallerLeft(parent context.Context, tier ModelTier) {
	if errors.Is(parent.Err(), context.Canceled) {
		applog.Info("ai.provider", "the request was cancelled while a model call ran; the call finished under its own budget",
			map[string]any{"tier": string(tier)})
	}
}

// FallbackNoteFor is the single footer line an evidence-only answer carries
// when the model was asked and did not narrate. A plain "nothing configured" or
// a generic failure keeps the historical note; a timeout, a paused provider and
// a spent budget say exactly that, because each asks something different of an
// administrator.
func FallbackNoteFor(err error) string {
	switch ClassifyProviderError(err) {
	case ProvTimeout:
		return NoteModelTimedOut
	case ProvBreakerOpen:
		return NoteModelPaused
	case ProvBudget:
		return NoteBudgetSpent
	}
	return ProviderFallbackNote(false)
}

// The disclosure lines. Pinned by tests; the UI shows them verbatim.
const (
	NoteModelTimedOut = "Model narrative timed out; showing the evidence answer."
	NoteModelPaused   = "AI model paused after repeated failures; showing the evidence answer."
	NoteBudgetSpent   = "Today's AI budget for this workspace is spent; showing the evidence answer."
)

// ── which model answered (C6 per-answer footnote) ───────────────────────────

// ModelNote collects the provider and model that answered within one request,
// so the orchestrator's single exit can name them on the Answer without the LLM
// seam's signature changing. Safe for concurrent use; nil-safe.
type ModelNote struct {
	mu       sync.Mutex
	provider string
	model    string
	// struck holds the failure that makes another call in the SAME request
	// pointless (ModelStruck), keyed by strikeKey: a whole provider ("gemini")
	// or one of its models ("gemini\x00gemini-flash-latest").
	struck map[string]error
	// timedOut is, per provider, the models that timed out in this request: a
	// second model of the same provider timing out strikes the provider.
	timedOut map[string]map[string]bool
}

// ── one strike per request (§9: never make the operator wait twice) ─────────
//
// Found live 2026-11-11: with the model provider timing out, "which devices
// are down right now?" took 28 s — the route tie-break (5 s), the rephrase
// (8 s) and the strong compile (8 s, whose failure finally opened the
// breaker) each waited out their own budget in turn, one after the other,
// before the deterministic answer was shown. The breaker is per (tenant,
// provider) across requests and needs three failures; within ONE request the
// first timeout is already the answer. After a provider fails a call in a way
// that will not change within seconds, every later model call of the same
// request skips that provider at once, and the request ends on the
// deterministic path, bounded by ONE model budget instead of the sum of them.

// strikes reports whether an outcome class makes a provider not worth a second
// call in the same request: it is slow or down (timeout, network, 5xx), out of
// quota, or refusing the key or model. A bad request shape or an empty answer
// is about that call's prompt, not the provider, so it does not strike.
func strikes(outcome string) bool {
	switch outcome {
	case ProvTimeout, ProvNetwork, ProvServer, ProvRateLimited, ProvAuth, ProvModelNotFound:
		return true
	}
	return false
}

// ModelSkippedError is a model call that was not made because the same model,
// or its whole provider, already failed in this request. It unwraps to that first failure,
// so the operator's footer and every classifier read the real reason
// ("timed out"), never a generic one.
type ModelSkippedError struct {
	Provider string
	Model    string // "" when the whole provider was struck
	First    error
}

func (e *ModelSkippedError) Error() string {
	who := e.Provider
	if e.Model != "" {
		who += " " + e.Model
	}
	return who + ": skipped — it already failed in this request: " + e.First.Error()
}

func (e *ModelSkippedError) Unwrap() error { return e.First }

// strikeKey names what a strike covers: the whole provider when model is "",
// else that one model of the provider.
func strikeKey(provider, model string) string {
	if model == "" {
		return provider
	}
	return provider + "\x00" + model
}

// ProviderWide reports whether an outcome class is a fact about the whole
// provider, not one model: the key is refused, or the provider cannot be
// reached at all. Everything else that strikes — overloaded (5xx), out of
// quota (quotas are per model at Google and OpenAI), model retired, or slow —
// is about the model asked for (found live 2026-11-12: Google answered 503
// "high demand" for gemini-flash-latest while gemini-2.5-flash answered the
// same key in 0.5 s; a provider-wide strike threw away the model that worked).
func ProviderWide(outcome string) bool {
	return outcome == ProvAuth || outcome == ProvNetwork
}

// NoteModelFailed records a failed call of (provider, model) on the request's
// note when its class strikes (a no-op without a note or for any other class).
// Key and network failures strike the provider; any other striking failure
// strikes only that model — except that when a SECOND model of the same
// provider times out in the same request, the provider is struck too, so a
// provider that hangs on every model costs at most two waits (the 2026-11-11
// "28 s" bound), not one per model.
func NoteModelFailed(ctx context.Context, provider, model string, err error) {
	n, _ := ctx.Value(modelNoteKey{}).(*ModelNote)
	if n == nil || err == nil {
		return
	}
	outcome := ClassifyProviderError(err)
	if !strikes(outcome) {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.struck == nil {
		n.struck = map[string]error{}
	}
	put := func(k string) {
		if _, ok := n.struck[k]; !ok {
			n.struck[k] = err
		}
	}
	if ProviderWide(outcome) || model == "" {
		put(strikeKey(provider, ""))
		return
	}
	put(strikeKey(provider, model))
	if outcome != ProvTimeout {
		return
	}
	if n.timedOut == nil {
		n.timedOut = map[string]map[string]bool{}
	}
	if n.timedOut[provider] == nil {
		n.timedOut[provider] = map[string]bool{}
	}
	n.timedOut[provider][model] = true
	if len(n.timedOut[provider]) >= 2 {
		put(strikeKey(provider, ""))
	}
}

// ModelStruck returns a *ModelSkippedError when (provider, model) — or the
// whole provider — already failed in this request (nil otherwise, and always
// nil without a note). model "" asks about the provider as a whole.
func ModelStruck(ctx context.Context, provider, model string) error {
	n, _ := ctx.Value(modelNoteKey{}).(*ModelNote)
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if first, ok := n.struck[strikeKey(provider, "")]; ok {
		return &ModelSkippedError{Provider: provider, First: first}
	}
	if model == "" {
		return nil
	}
	if first, ok := n.struck[strikeKey(provider, model)]; ok {
		return &ModelSkippedError{Provider: provider, Model: model, First: first}
	}
	return nil
}

type modelNoteKey struct{}

// WithModelNote returns a context carrying a fresh note (or the existing one).
func WithModelNote(ctx context.Context) (context.Context, *ModelNote) {
	if n, ok := ctx.Value(modelNoteKey{}).(*ModelNote); ok && n != nil {
		return ctx, n
	}
	n := &ModelNote{}
	return context.WithValue(ctx, modelNoteKey{}, n), n
}

// NoteModelUsed records the model that answered on the request's note (a
// no-op when the context carries none).
func NoteModelUsed(ctx context.Context, provider, model string) {
	n, _ := ctx.Value(modelNoteKey{}).(*ModelNote)
	if n == nil {
		return
	}
	n.mu.Lock()
	n.provider, n.model = provider, model
	n.mu.Unlock()
}

// Model returns the model recorded for provider ("" when none or a different
// provider answered last).
func (n *ModelNote) Model(provider string) string {
	if n == nil {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.provider != provider {
		return ""
	}
	return n.model
}
