package main

// wireless_actions.go — guarded wireless remediation (#128 Phase 8, design
// docs/Wireslessdesign.md §19). FIVE GATES, all mandatory, in order — an
// action that has not passed every gate cannot run, structurally:
//
//	1 PROPOSAL      the action's evidence family must have PARTICIPATED in the
//	                correlation object it claims to remediate (the rca_actions
//	                rule: never propose from a title)
//	2 ELIGIBILITY   per-tenant allowlist (default EMPTY — nothing is eligible
//	                until an operator opts a type in), verdict must be
//	                `confirmed` (suspected/undetermined never auto-remediate),
//	                blast radius bound to ONE typed target
//	3 APPROVAL      a named human approver; per-type auto-approve is opt-in,
//	                off by default, and audited as itself
//	4 EXECUTION     idempotent, timeout-bounded, via the vendor connector ONLY
//	                (never raw SSH — device_ssh.go stays a human terminal).
//	                v1 registers NO executor: execution fails CLOSED with
//	                "no executor" until the vendor write RPC earns live
//	                validation (Phase 9). The gates ship first, on purpose.
//	5 VERIFICATION  after execution the originating signal is re-measured in a
//	                settle window; not-recovered → rollback where possible and
//	                the action records FAILED. Never fire-and-forget.
//
// FEATURE_WIRELESS_ACTIONS=false (default) keeps the whole surface dormant:
// the handlers 404, matching the platform's dormant-by-default convention
// (FEATURE_DEVICE_SSH, FEATURE_TRACEROUTE). State is in-memory by design at
// this phase — a dormant framework must not add a migration; durability lands
// with the first real executor.
//
// Every transition is an audit event. §3a: requests are tenant-scoped in the
// store; cross-tenant ids 404.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The three v1 actions — deliberately the lowest-risk (report §19); anything
// touching more than one AP in one action is out of scope by design.
const (
	WirelessActionRRMChannel   = "rrm_channel_change" // 1 radio, brief re-assoc
	WirelessActionRadioReset   = "ap_radio_reset"     // 1 AP's radio
	WirelessActionClientDeauth = "client_deauth"      // 1 client session
)

var wirelessActionKinds = map[string]struct {
	targetPrefix string // the canonical entity prefix the target must carry
	evidence     []string
}{
	WirelessActionRRMChannel:   {"ap-", []string{"wireless_channel_util_high", "wireless_interference", "wireless_noise_high", "wireless_radar_event"}},
	WirelessActionRadioReset:   {"ap-", []string{"wireless_radio_down", "wireless_retry_rate_high", "wireless_ap_join_flap"}},
	WirelessActionClientDeauth: {"wcl-", []string{"wireless_roam_storm", "wireless_client_disconnect_storm", "wireless_onboarding_auth_failure"}},
}

type wirelessActionState string

const (
	wactProposed wirelessActionState = "proposed"
	wactApproved wirelessActionState = "approved"
	wactExecuted wirelessActionState = "executed"
	wactVerified wirelessActionState = "verified"
	wactFailed   wirelessActionState = "failed"
	wactRejected wirelessActionState = "rejected"
)

type wirelessAction struct {
	Tenant        string              `json:"-"`
	ID            string              `json:"id"`
	Kind          string              `json:"kind"`
	Target        string              `json:"target"` // ONE canonical entity id
	CorrelationID string              `json:"correlation_id"`
	State         wirelessActionState `json:"state"`
	ProposedBy    string              `json:"proposed_by"`
	ApprovedBy    string              `json:"approved_by,omitempty"`
	Error         string              `json:"error,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
	// Verification outcome (gate 5): set by the settle-window recheck.
	VerifyNote string `json:"verify_note,omitempty"`
}

// wirelessActionExecutor is gate 4's seam: the vendor-connector write RPC.
// v1 registers NONE — execution fails closed. NEVER implement this over SSH.
type wirelessActionExecutor interface {
	Execute(a wirelessAction) error
}

type wirelessActionStore struct {
	mu   sync.Mutex
	rows map[string]map[string]*wirelessAction // tenant → id → action
	seq  int
	exec wirelessActionExecutor // nil = fail closed (v1)
}

func newWirelessActionStore() *wirelessActionStore {
	return &wirelessActionStore{rows: map[string]map[string]*wirelessAction{}}
}

func wirelessActionsEnabled() bool {
	return os.Getenv("FEATURE_WIRELESS_ACTIONS") == "true"
}

// wirelessActionAllowlist — gate 2's per-tenant type allowlist. v1 source is
// the env (WIRELESS_ACTION_ALLOWLIST="rrm_channel_change,client_deauth"),
// applied to every tenant; empty = NOTHING eligible. Per-tenant config lands
// with durability.
func wirelessActionAllowlist() map[string]bool {
	out := map[string]bool{}
	for _, k := range strings.Split(os.Getenv("WIRELESS_ACTION_ALLOWLIST"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = true
		}
	}
	return out
}

var (
	errWActUnknownKind  = errors.New("unknown wireless action kind")
	errWActEvidence     = errors.New("gate 1: the action's evidence family did not participate in the correlation object")
	errWActNotAllowed   = errors.New("gate 2: action kind is not in the tenant allowlist")
	errWActNotConfirmed = errors.New("gate 2: verdict is not confirmed — suspected/undetermined never auto-remediate")
	errWActBlastRadius  = errors.New("gate 2: blast radius — the target must be exactly one entity of the action's type")
	errWActNotApproved  = errors.New("gate 3: action is not approved")
	errWActNoExecutor   = errors.New("gate 4: no executor registered — the vendor write RPC has not earned live validation (Phase 9)")
	errWActWrongState   = errors.New("action is not in a state that permits this transition")
)

// propose runs gates 1 + 2 and records the request. participatingKinds and
// verdictTier come from the correlation object the caller names (the handler
// fetches them; tests inject them).
func (st *wirelessActionStore) propose(tenant, actor string, kind, target, correlationID string,
	participatingKinds []string, verdictTier string) (*wirelessAction, error) {
	spec, ok := wirelessActionKinds[kind]
	if !ok {
		return nil, errWActUnknownKind
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
		return nil, errWActEvidence
	}
	// Gate 2 — eligibility.
	if !wirelessActionAllowlist()[kind] {
		return nil, errWActNotAllowed
	}
	if verdictTier != "confirmed" {
		return nil, errWActNotConfirmed
	}
	if target == "" || !strings.HasPrefix(target, spec.targetPrefix) ||
		strings.ContainsAny(target, ", \t") {
		return nil, errWActBlastRadius
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.seq++
	a := &wirelessAction{
		Tenant: tenant, ID: fmt.Sprintf("wact-%d", st.seq), Kind: kind,
		Target: target, CorrelationID: correlationID, State: wactProposed,
		ProposedBy: actor, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	t := st.rows[tenant]
	if t == nil {
		t = map[string]*wirelessAction{}
		st.rows[tenant] = t
	}
	t[a.ID] = a
	return a, nil
}

// approve runs gate 3: a named human approver. (Auto-approve, when it lands,
// calls this with actor "auto:<policy>" and its OWN audit event — never
// silently.)
func (st *wirelessActionStore) approve(tenant, id, approver string) (*wirelessAction, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, errNotFound
	}
	if a.State != wactProposed {
		return nil, errWActWrongState
	}
	a.State = wactApproved
	a.ApprovedBy = approver
	a.UpdatedAt = time.Now().UTC()
	return a, nil
}

// reject is the approver's other verb.
func (st *wirelessActionStore) reject(tenant, id, approver string) (*wirelessAction, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, errNotFound
	}
	if a.State != wactProposed {
		return nil, errWActWrongState
	}
	a.State = wactRejected
	a.ApprovedBy = approver
	a.UpdatedAt = time.Now().UTC()
	return a, nil
}

// execute runs gate 4. Fail-closed: no registered executor = refusal, and a
// failed execution records FAILED (never silently retried).
func (st *wirelessActionStore) execute(tenant, id string) (*wirelessAction, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	a := st.rows[tenant][id]
	if a == nil {
		return nil, errNotFound
	}
	if a.State != wactApproved {
		if a.State == wactProposed {
			return nil, errWActNotApproved
		}
		return nil, errWActWrongState
	}
	if st.exec == nil {
		a.State = wactFailed
		a.Error = errWActNoExecutor.Error()
		a.UpdatedAt = time.Now().UTC()
		return a, errWActNoExecutor
	}
	if err := st.exec.Execute(*a); err != nil {
		a.State = wactFailed
		a.Error = err.Error()
		a.UpdatedAt = time.Now().UTC()
		return a, err
	}
	a.State = wactExecuted
	a.UpdatedAt = time.Now().UTC()
	// Gate 5 begins here when an executor exists: the settle-window recheck of
	// the originating signal marks verified/failed. Recorded as pending so a
	// fire-and-forget can never masquerade as done.
	a.VerifyNote = "verification pending: settle-window recheck of the originating signal"
	return a, nil
}

func (st *wirelessActionStore) list(tenant string, cross bool) []*wirelessAction {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []*wirelessAction
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

func (s *server) wirelessActionAudit(r *http.Request, claims jwtClaims, action string, a *wirelessAction, decision string) {
	if s.audit == nil {
		return
	}
	tenant, cross := principalTenant(claims)
	detail := map[string]any{"action": action}
	if a != nil {
		detail["kind"] = a.Kind
		detail["target"] = a.Target
		detail["state"] = string(a.State)
		detail["correlation_id"] = a.CorrelationID
		detail["id"] = a.ID
	}
	s.audit.Record(AuditEvent{
		Time: time.Now().UTC(), Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: r.Method, Path: r.URL.Path, Status: 200, Decision: decision,
		Detail: detail,
	})
}

// handleWirelessActions — POST /api/wireless/actions (propose) + GET (list).
func (s *server) handleWirelessActions(w http.ResponseWriter, r *http.Request) {
	if !wirelessActionsEnabled() {
		http.NotFound(w, r)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.wirelessActions.list(tenant, cross))
	case http.MethodPost:
		var in struct {
			Kind          string `json:"kind"`
			Target        string `json:"target"`
			CorrelationID string `json:"correlation_id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		kinds, tier, err := s.wirelessActionGateInputs(r, in.CorrelationID)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("gate inputs: %w", err))
			return
		}
		a, err := s.wirelessActions.propose(tenant, claims.Sub, in.Kind, in.Target,
			in.CorrelationID, kinds, tier)
		if err != nil {
			s.wirelessActionAudit(r, claims, "propose", a, "deny")
			writeError(w, http.StatusUnprocessableEntity, err)
			return
		}
		s.wirelessActionAudit(r, claims, "propose", a, "allow")
		writeJSON(w, http.StatusCreated, a)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleWirelessActionItem — POST /api/wireless/actions/{id}/{approve|reject|execute}.
func (s *server) handleWirelessActionItem(w http.ResponseWriter, r *http.Request) {
	if !wirelessActionsEnabled() {
		http.NotFound(w, r)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := principalTenant(claims)
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/wireless/actions/"), "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	id, verb := parts[0], parts[1]
	var (
		a   *wirelessAction
		err error
	)
	switch verb {
	case "approve":
		a, err = s.wirelessActions.approve(tenant, id, claims.Sub)
	case "reject":
		a, err = s.wirelessActions.reject(tenant, id, claims.Sub)
	case "execute":
		a, err = s.wirelessActions.execute(tenant, id)
	default:
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, errNotFound) {
		// Cross-tenant and unknown ids are indistinguishable (§3a).
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.wirelessActionAudit(r, claims, verb, a, "deny")
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	s.wirelessActionAudit(r, claims, verb, a, "allow")
	writeJSON(w, http.StatusOK, a)
}

// wirelessActionGateInputs fetches gate-1/2 inputs (participating kinds +
// verdict tier) from the named correlation object — TENANT-SCOPED reads (the
// row policies enforce it server-side). Without a reachable ClickHouse the
// gates FAIL CLOSED: no inputs, no proposal — never "assume confirmed".
func (s *server) wirelessActionGateInputs(r *http.Request, correlationID string) ([]string, string, error) {
	if correlationID == "" {
		return nil, "", errors.New("correlation_id is required — actions are proposed from incidents, not free-form")
	}
	if !isUUIDToken(correlationID) {
		return nil, "", errors.New("correlation_id must be a UUID")
	}
	tierRows, err := s.chRows(r, `
SELECT verdict_tier FROM netops.corr_current
 WHERE correlation_id = '`+correlationID+`' LIMIT 1`)
	if err != nil {
		return nil, "", err
	}
	if len(tierRows) == 0 {
		return nil, "", errNotFound
	}
	kindRows, err := s.chRows(r, `
SELECT DISTINCT kind FROM netops.corr_signals_archive
 WHERE archived_for = '`+correlationID+`' LIMIT 200`)
	if err != nil {
		return nil, "", err
	}
	kinds := make([]string, 0, len(kindRows))
	for _, row := range kindRows {
		if k := asStr(row["kind"]); k != "" {
			kinds = append(kinds, k)
		}
	}
	return kinds, asStr(tierRows[0]["verdict_tier"]), nil
}
