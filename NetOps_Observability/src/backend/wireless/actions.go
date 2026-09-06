// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wireless

// actions.go — the guarded wireless remediation register (Phase-2 W4.6,
// extracted from package main's wireless_actions.go): the closed action-kind
// vocabulary, the five-gate propose→approve→execute state machine (actor and
// approver must differ; every transition validated), the bounded in-memory
// per-tenant store and the executor seam. Feature gating (env), the audit
// writer, gate-input resolution and the handlers stay in main.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	WirelessActionRRMChannel   = "rrm_channel_change" // 1 radio, brief re-assoc
	WirelessActionRadioReset   = "ap_radio_reset"     // 1 AP's radio
	WirelessActionClientDeauth = "client_deauth"      // 1 client session
)

var ActionKinds = map[string]struct {
	targetPrefix string // the canonical entity prefix the target must carry
	evidence     []string
}{
	WirelessActionRRMChannel:   {"ap-", []string{"wireless_channel_util_high", "wireless_interference", "wireless_noise_high", "wireless_radar_event"}},
	WirelessActionRadioReset:   {"ap-", []string{"wireless_radio_down", "wireless_retry_rate_high", "wireless_ap_join_flap"}},
	WirelessActionClientDeauth: {"wcl-", []string{"wireless_roam_storm", "wireless_client_disconnect_storm", "wireless_onboarding_auth_failure"}},
}

type ActionState string

const (
	ActionStateProposed ActionState = "proposed"
	ActionStateApproved ActionState = "approved"
	ActionStateExecuted ActionState = "executed"
	ActionStateVerified ActionState = "verified"
	ActionStateFailed   ActionState = "failed"
	ActionStateRejected ActionState = "rejected"
)

type Action struct {
	Tenant        string      `json:"-"`
	ID            string      `json:"id"`
	Kind          string      `json:"kind"`
	Target        string      `json:"target"` // ONE canonical entity id
	CorrelationID string      `json:"correlation_id"`
	State         ActionState `json:"state"`
	ProposedBy    string      `json:"proposed_by"`
	ApprovedBy    string      `json:"approved_by,omitempty"`
	// Reason is the approver's own words for the decision, recorded on the
	// action and in the audit event. REQUIRED on a rejection: a refusal nobody
	// wrote a reason for is the audit gap this workflow exists to close.
	Reason    string    `json:"reason,omitempty"`
	Error     string    `json:"error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	// Verification outcome (gate 5): set by the settle-window recheck.
	VerifyNote string `json:"verify_note,omitempty"`
}

// ActionExecutor is gate 4's seam: the vendor-connector write RPC.
// v1 registers NONE — execution fails closed. NEVER implement this over SSH.
type ActionExecutor interface {
	Execute(a Action) error
}

type ActionStore struct {
	mu   sync.Mutex
	rows map[string]map[string]*Action // tenant → id → action
	seq  int
	exec ActionExecutor // nil = fail closed (v1)
}

func NewActionStore() *ActionStore {
	return &ActionStore{rows: map[string]map[string]*Action{}}
}

// ErrActionNotFound is the default-closed lookup failure (cross-tenant ids
// included — existence is never revealed).
var ErrActionNotFound = errors.New("action not found")

var (
	ErrActionUnknownKind  = errors.New("unknown wireless action kind")
	ErrActionEvidence     = errors.New("gate 1: the action's evidence family did not participate in the correlation object")
	ErrActionNotAllowed   = errors.New("gate 2: action kind is not in the tenant allowlist")
	ErrActionNotConfirmed = errors.New("gate 2: verdict is not confirmed — suspected/undetermined never auto-remediate")
	ErrActionBlastRadius  = errors.New("gate 2: blast radius — the target must be exactly one entity of the action's type")
	ErrActionNotApproved  = errors.New("gate 3: action is not approved")
	ErrActionNoExecutor   = errors.New("gate 4: no executor registered — the vendor write RPC has not earned live validation (Phase 9)")
	ErrActionWrongState   = errors.New("action is not in a state that permits this transition")
	ErrActionNoReason     = errors.New("gate 3: a rejection must state its reason")
)

// propose runs gates 1 + 2 and records the request. participatingKinds and
// verdictTier come from the correlation object the caller names (the handler
// fetches them; tests inject them).
func (st *ActionStore) Propose(tenant, actor string, kind, target, correlationID string,
	participatingKinds []string, verdictTier string, allowed map[string]bool) (*Action, error) {
	spec, ok := ActionKinds[kind]
	if !ok {
		return nil, ErrActionUnknownKind
	}
	// Gate 1 — proposal from participating evidence only.
	part := map[string]bool{}
	for _, k := range participatingKinds {
		part[k] = true
	}
	matched := false
	for _, k := range spec.evidence {
		if part[k] {
			matched = true
			break
		}
	}
	if !matched {
		return nil, ErrActionEvidence
	}
	// Gate 2 — eligibility.
	if !allowed[kind] {
		return nil, ErrActionNotAllowed
	}
	if verdictTier != "confirmed" {
		return nil, ErrActionNotConfirmed
	}
	if target == "" || !strings.HasPrefix(target, spec.targetPrefix) ||
		strings.ContainsAny(target, ", \t") {
		return nil, ErrActionBlastRadius
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.seq++
	a := &Action{
		Tenant: tenant, ID: fmt.Sprintf("wact-%d", st.seq), Kind: kind,
		Target: target, CorrelationID: correlationID, State: ActionStateProposed,
		ProposedBy: actor, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	t := st.rows[tenant]
	if t == nil {
		t = map[string]*Action{}
		st.rows[tenant] = t
	}
	t[a.ID] = a
	return a, nil
}

// MaxActionReason bounds the approver's free text. Validated at the boundary
// (§3): the note is stored, audited and rendered, so it is length-capped here
// rather than trusted to be short.
const MaxActionReason = 500

// NormalizeReason trims the approver's note and rejects one that is too long.
// Exported so the handler validates with the SAME rule the store applies.
func NormalizeReason(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > MaxActionReason {
		return "", fmt.Errorf("reason is longer than %d characters", MaxActionReason)
	}
	return s, nil
}

// approve runs gate 3: a named human approver. (Auto-approve, when it lands,
// calls this with actor "auto:<policy>" and its OWN audit event — never
// silently.) `reason` is the approver's optional note.
func (st *ActionStore) Approve(tenant, id, approver, reason string) (*Action, error) {
	reason, rerr := NormalizeReason(reason)
	if rerr != nil {
		return nil, rerr
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, ErrActionNotFound
	}
	if a.State != ActionStateProposed {
		return nil, ErrActionWrongState
	}
	a.State = ActionStateApproved
	a.ApprovedBy = approver
	a.Reason = reason
	a.UpdatedAt = time.Now().UTC()
	return a, nil
}

// reject is the approver's other verb. Unlike an approval it REQUIRES a reason:
// the proposal came from correlated evidence, so "we did not do this, and here
// is why" is the record the next operator reads before proposing it again.
func (st *ActionStore) Reject(tenant, id, approver, reason string) (*Action, error) {
	reason, rerr := NormalizeReason(reason)
	if rerr != nil {
		return nil, rerr
	}
	if reason == "" {
		return nil, ErrActionNoReason
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, ErrActionNotFound
	}
	if a.State != ActionStateProposed {
		return nil, ErrActionWrongState
	}
	a.State = ActionStateRejected
	a.ApprovedBy = approver
	a.Reason = reason
	a.UpdatedAt = time.Now().UTC()
	return a, nil
}

// execute runs gate 4. Fail-closed: no registered executor = refusal, and a
// failed execution records FAILED (never silently retried).
func (st *ActionStore) Execute(tenant, id string) (*Action, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, ErrActionNotFound
	}
	if a.State != ActionStateApproved {
		if a.State == ActionStateProposed {
			return nil, ErrActionNotApproved
		}
		return nil, ErrActionWrongState
	}
	if st.exec == nil {
		a.State = ActionStateFailed
		a.Error = ErrActionNoExecutor.Error()
		a.UpdatedAt = time.Now().UTC()
		return a, ErrActionNoExecutor
	}
	if err := st.exec.Execute(*a); err != nil {
		a.State = ActionStateFailed
		a.Error = err.Error()
		a.UpdatedAt = time.Now().UTC()
		return a, err
	}
	a.State = ActionStateExecuted
	a.UpdatedAt = time.Now().UTC()
	// Gate 5 begins here when an executor exists: the settle-window recheck of
	// the originating signal marks verified/failed. Recorded as pending so a
	// fire-and-forget can never masquerade as done.
	a.VerifyNote = "verification pending: settle-window recheck of the originating signal"
	return a, nil
}

func (st *ActionStore) List(tenant string, cross bool) []*Action {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []*Action
	for t, rows := range st.rows {
		if !cross && t != tenant {
			continue
		}
		for _, a := range rows {
			cp := *a
			out = append(out, &cp)
		}
	}
	return out
}

// ── HTTP surface (dormant unless FEATURE_WIRELESS_ACTIONS=true) ─────────────
