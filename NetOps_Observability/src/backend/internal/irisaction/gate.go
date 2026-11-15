// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisaction

// gate.go — ApprovalGate[T]: the five gates as one reusable mechanism, with
// one typed executor per kind, driven by the Service.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Executor sends one kind of write. DryRun is read-only (it may probe — "does
// the ticket still exist?" — but changes nothing). Execute performs the write
// exactly once per idempotency key; the Service guarantees it is called at
// most once per request.
type Executor[T Payload] interface {
	// Describe renders the operator summary line and the EXACT text that will
	// be sent — what the approver approves.
	Describe(p T) (summary, preview string)
	DryRun(ctx context.Context, tenant string, p T) DryRun
	Execute(ctx context.Context, tenant string, p T, idempotencyKey string) (Result, error)
}

// ApprovalGate binds one Kind to its typed executor.
type ApprovalGate[T Payload] struct {
	kind Kind
	exec Executor[T]
}

// kindGate is the type-erased view the Service keeps per kind.
type kindGate interface {
	gateKind() Kind
	prepare(ctx context.Context, tenant string, p Payload) (summary, preview string, dry DryRun, err error)
	execute(ctx context.Context, tenant string, raw []byte, key string) (Result, error)
}

func (g *ApprovalGate[T]) gateKind() Kind { return g.kind }

func (g *ApprovalGate[T]) prepare(ctx context.Context, tenant string, p Payload) (string, string, DryRun, error) {
	t, ok := p.(T)
	if !ok {
		return "", "", DryRun{}, fmt.Errorf("%w: payload is not a %s", ErrInvalid, g.kind)
	}
	summary, preview := g.exec.Describe(t)
	return clip(summary, 300), clip(preview, MaxNoteChars+MaxTitleChars+64), g.exec.DryRun(ctx, tenant, t), nil
}

func (g *ApprovalGate[T]) execute(ctx context.Context, tenant string, raw []byte, key string) (Result, error) {
	p, err := DecodePayload(g.kind, raw)
	if err != nil {
		return Result{}, err
	}
	t, ok := p.(T)
	if !ok {
		return Result{}, fmt.Errorf("%w: stored payload is not a %s", ErrInvalid, g.kind)
	}
	return g.exec.Execute(ctx, tenant, t, key)
}

// Service drives proposals, decisions and execution over one Store.
type Service struct {
	store Store
	gates map[Kind]kindGate
	// Now and TTL are injectable for tests.
	Now func() time.Time
	TTL time.Duration
}

// NewService builds a Service with no executors registered.
func NewService(store Store) *Service {
	return &Service{store: store, gates: map[Kind]kindGate{}, Now: time.Now, TTL: DefaultTTL}
}

// Register binds kind k to its executor. The executor's payload type must be
// k's: registering an ITSMNote executor under investigation_note is refused.
func Register[T Payload](s *Service, k Kind, e Executor[T]) error {
	var zero T
	if !ValidKind(k) || zero.kind() != k {
		return fmt.Errorf("%w: executor payload does not match kind %q", ErrInvalid, k)
	}
	if e == nil {
		return fmt.Errorf("%w: nil executor for %q", ErrInvalid, k)
	}
	s.gates[k] = &ApprovalGate[T]{kind: k, exec: e}
	return nil
}

// Registered reports whether kind k has an executor.
func (s *Service) Registered(k Kind) bool {
	_, ok := s.gates[k]
	return ok
}

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now().UTC()
}

func (s *Service) ttl() time.Duration {
	if s.TTL <= 0 {
		return DefaultTTL
	}
	return s.TTL
}

// Proposal is gate 1's input: a server-built payload and where it came from.
type Proposal struct {
	Payload    Payload
	ProposedBy string   // the person Iris answered
	DecisionID string   // the proposing answer's ledger decision id
	Citations  []string // the evidence it rests on (proposed_from)
}

// ProposeOutcome is what Propose decided.
type ProposeOutcome struct {
	Request  Request
	Decision Decision
	Reason   string
	// Existing: an identical request (same kind, same case) was already
	// waiting, and it is returned instead of a duplicate.
	Existing bool
}

// Propose runs gates 1–2 and stores the request. A DENY stores nothing and
// returns ErrDenied with the reason; DRY_RUN_ONLY stores a terminal dry-run
// request; REQUIRE_APPROVAL stores a request waiting for a different person.
func (s *Service) Propose(ctx context.Context, tenant string, env Env, in Proposal) (ProposeOutcome, error) {
	k := KindOf(in.Payload)
	decision, reason := Evaluate(k, env)
	out := ProposeOutcome{Decision: decision, Reason: reason}
	if decision == Deny {
		return out, fmt.Errorf("%w: %s", ErrDenied, reason)
	}
	if decision == Allow {
		// Unreachable by construction (Evaluate never allows a write); refuse
		// rather than execute without a person if that ever changes.
		return out, fmt.Errorf("%w: a write is never run without approval", ErrDenied)
	}
	if tenant == "" || in.ProposedBy == "" {
		return out, fmt.Errorf("%w: tenant and proposer are required", ErrInvalid)
	}
	if err := Validate(in.Payload); err != nil {
		return out, err
	}
	g, ok := s.gates[k]
	if !ok {
		return out, ErrNoExecutor
	}
	corr := correlationOf(in.Payload)
	if decision == RequireApproval {
		prev, ok, err := s.waiting(ctx, tenant, k, corr)
		if err != nil {
			return out, err
		}
		if ok {
			out.Request, out.Existing = prev, true
			return out, nil
		}
	}
	raw, err := EncodePayload(in.Payload)
	if err != nil {
		return out, err
	}
	summary, preview, dry, err := g.prepare(ctx, tenant, in.Payload)
	if err != nil {
		return out, err
	}
	id, err := NewID()
	if err != nil {
		return out, err
	}
	now := s.now()
	status := StatusProposed
	if decision == DryRunOnly {
		status = StatusDryRun
	}
	r := Request{
		TenantID: tenant, ID: id, Kind: k,
		ProposedBy: clip(in.ProposedBy, 256), ProposedVia: "iris", DecisionID: clip(in.DecisionID, 64),
		CorrelationID: corr, Citations: cleanCitations(in.Citations),
		Payload: raw, Summary: summary, Preview: preview, DryRun: dry,
		Policy: decision, Status: status, CreatedAt: now, ExpiresAt: now.Add(s.ttl()),
	}
	if err := s.store.Insert(ctx, r); err != nil {
		return out, err
	}
	out.Request = r
	return out, nil
}

// waiting finds a request of this kind for this case that is still waiting.
// A store that cannot answer is an error, never "none waiting" — otherwise a
// read outage would quietly mint duplicates.
func (s *Service) waiting(ctx context.Context, tenant string, k Kind, corr string) (Request, bool, error) {
	open, err := s.store.List(ctx, tenant, Filter{Status: StatusProposed})
	if err != nil {
		return Request{}, false, err
	}
	now := s.now()
	for _, r := range open {
		if r.Kind == k && r.CorrelationID == corr && now.Before(r.ExpiresAt) {
			return r, true, nil
		}
	}
	return Request{}, false, nil
}

func correlationOf(p Payload) string {
	switch v := p.(type) {
	case ITSMNote:
		return v.CorrelationID
	case InvestigationNote:
		return v.CorrelationID
	}
	return ""
}

// Get returns one request, marking it expired first when its time has passed.
func (s *Service) Get(ctx context.Context, tenant, id string) (Request, error) {
	r, err := s.store.Get(ctx, tenant, id)
	if err != nil {
		return Request{}, err
	}
	return s.expireIfDue(ctx, tenant, r), nil
}

// List returns the tenant's requests, newest first, expiring due ones first.
func (s *Service) List(ctx context.Context, tenant string, f Filter) ([]Request, error) {
	rs, err := s.store.List(ctx, tenant, f)
	if err != nil {
		return nil, err
	}
	for i := range rs {
		rs[i] = s.expireIfDue(ctx, tenant, rs[i])
	}
	if f.Status != "" {
		kept := rs[:0]
		for _, r := range rs {
			if r.Status == f.Status {
				kept = append(kept, r)
			}
		}
		rs = kept
	}
	return rs, nil
}

func (s *Service) expireIfDue(ctx context.Context, tenant string, r Request) Request {
	if r.Status != StatusProposed || s.now().Before(r.ExpiresAt) {
		return r
	}
	next, err := s.store.Update(ctx, tenant, r.ID, StatusProposed, func(x *Request) error {
		x.Status = StatusExpired
		return nil
	})
	switch {
	case errors.Is(err, ErrNotPending):
		return next // someone decided it meanwhile: show what is stored now
	case err != nil:
		return r // the store could not mark it; the next read retries
	}
	return next
}

// Approve runs gates 3–5 for one request: a different person, the policy
// re-checked NOW (a kill switch turned off after the proposal stops it), the
// compare-and-set claim, exactly one execution, the recorded result.
//
// A request that already ran returns its stored result with ErrNotPending: a
// retried or double-clicked approval never sends twice.
func (s *Service) Approve(ctx context.Context, tenant, approver string, env Env, id, reason string) (Request, error) {
	r, err := s.Get(ctx, tenant, id)
	if err != nil {
		return Request{}, err
	}
	switch r.Status {
	case StatusProposed:
	case StatusExpired:
		return r, ErrExpired
	default:
		return r, ErrNotPending
	}
	if approver == "" || approver == r.ProposedBy {
		return r, ErrSelfApproval
	}
	switch d, why := Evaluate(r.Kind, env); d {
	case RequireApproval:
	case DryRunOnly:
		return r, ErrDryRunOnly
	default:
		return r, fmt.Errorf("%w: %s", ErrDenied, why)
	}
	g, ok := s.gates[r.Kind]
	if !ok {
		return r, ErrNoExecutor
	}
	now := s.now()
	claimed, err := s.store.Update(ctx, tenant, id, StatusProposed, func(x *Request) error {
		x.Status = StatusExecuting
		x.DecidedBy = clip(approver, 256)
		x.DecidedAt = &now
		x.Reason = clip(reason, MaxReasonChars)
		return nil
	})
	if err != nil {
		return claimed, err // ErrNotPending: someone else's approval won the claim
	}
	res, execErr := g.execute(ctx, tenant, claimed.Payload, claimed.ID)
	done := s.now()
	final, err := s.store.Update(ctx, tenant, id, StatusExecuting, func(x *Request) error {
		x.ExecutedAt = &done
		if execErr != nil {
			x.Status = StatusFailed
			x.Result = &Result{Message: clip(execErr.Error(), 300)}
			return nil
		}
		x.Status = StatusExecuted
		res.Message = clip(res.Message, 300)
		res.ExternalRef = clip(res.ExternalRef, MaxKeyChars)
		res.URL = clip(res.URL, 512)
		x.Result = &res
		return nil
	})
	if err != nil {
		return final, err
	}
	if execErr != nil {
		return final, fmt.Errorf("the action was approved but sending it failed: %w", execErr)
	}
	return final, nil
}

// Reject declines a waiting request with a reason. Anyone allowed to decide
// may decline it, including the person Iris answered (withdrawing it).
func (s *Service) Reject(ctx context.Context, tenant, actor, id, reason string) (Request, error) {
	if clip(reason, MaxReasonChars) == "" {
		return Request{}, ErrReasonMissing
	}
	r, err := s.Get(ctx, tenant, id)
	if err != nil {
		return Request{}, err
	}
	if r.Status != StatusProposed {
		if r.Status == StatusExpired {
			return r, ErrExpired
		}
		return r, ErrNotPending
	}
	now := s.now()
	return s.store.Update(ctx, tenant, id, StatusProposed, func(x *Request) error {
		x.Status = StatusRejected
		x.DecidedBy = clip(actor, 256)
		x.DecidedAt = &now
		x.Reason = clip(reason, MaxReasonChars)
		return nil
	})
}

// IsConflict reports whether err means "not waiting any more" (HTTP 409).
func IsConflict(err error) bool {
	return errors.Is(err, ErrNotPending) || errors.Is(err, ErrExpired)
}
