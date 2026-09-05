package backend

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
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/wireless"
)

// The three v1 actions — deliberately the lowest-risk (report §19); anything
// touching more than one AP in one action is out of scope by design.
// The action state machine moved to wireless/actions.go (Phase-2 W4.6).
type (
	wirelessAction      = wireless.Action
	wirelessActionStore = wireless.ActionStore
)

func newWirelessActionStore() *wirelessActionStore { return wireless.NewActionStore() }

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
		if a.Reason != "" {
			detail["reason"] = a.Reason
		}
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
		writeJSON(w, http.StatusOK, s.wirelessActions.List(tenant, cross))
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
		a, err := s.wirelessActions.Propose(tenant, claims.Sub, in.Kind, in.Target,
			in.CorrelationID, kinds, tier, wirelessActionAllowlist())
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

// wirelessActionReason reads the approver's note off the request. An EMPTY body
// is legitimate (approve and execute need no note), a body that is not the
// expected object is not: an unreadable payload must never be silently treated
// as "no reason given" on a route where the absence of a reason is itself a
// decision the store acts on.
func wirelessActionReason(w http.ResponseWriter, r *http.Request) (string, error) {
	var in struct {
		Reason string `json:"reason"`
	}
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in)
	if errors.Is(err, io.EOF) {
		return "", nil // no body at all
	}
	if err != nil {
		return "", err
	}
	return wireless.NormalizeReason(in.Reason)
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
	// The approver's note. Bounded and OPTIONAL on the wire — a body-less POST
	// stays valid (the shape the CLI used before the approval queue had a UI) —
	// but the store still refuses a rejection that carries no reason.
	reason, err := wirelessActionReason(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var a *wirelessAction
	switch verb {
	case "approve":
		a, err = s.wirelessActions.Approve(tenant, id, claims.Sub, reason)
	case "reject":
		a, err = s.wirelessActions.Reject(tenant, id, claims.Sub, reason)
	case "execute":
		a, err = s.wirelessActions.Execute(tenant, id)
	default:
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, wireless.ErrActionNotFound) || errors.Is(err, errNotFound) {
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
