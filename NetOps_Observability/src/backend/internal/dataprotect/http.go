// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// http.go — the Data Protection routes.
//
// Every handler follows the same order, and the order IS the guarantee:
//
//  1. GATE FIRST, before the verb or the body is even looked at. A tenant admin
//     holds full administration:admin, so a scope-blind gate here would hand
//     every tenant the platform's backup posture AND the ability to delete its
//     restore points (§3a rule 3). The gate must run BEFORE any OpenSearch call,
//     which the route tests assert with a request counter.
//  2. BOUND the body (MaxBytesReader) and VALIDATE every field against a closed
//     grammar.
//  3. AUDIT both outcomes — a refused platform-global write that was never
//     recorded is indistinguishable from one that never happened.

// maxRequestBody bounds a control-plane write body (§9, §15's MaxBytesReader
// discipline applies to every write surface, not just the LLM ones).
const maxRequestBody = 16 << 10

// ready reports whether the module was actually built. A server assembled
// without it — a narrow unit harness that still registers the full route table
// — must answer 503 rather than panic inside a data-protection route (§10: no
// silent failure, and no crash either). It is deliberately NOT the injected
// writer: the thing being guarded against is that writer being absent.
func (s *Service) ready(w http.ResponseWriter) bool {
	if s != nil && s.deps.Authz != nil && s.deps.WriteJSON != nil {
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	// There is no injected writer and no injected logger to fall back to here —
	// their absence is precisely the condition being reported.
	// best-effort: the 503 status line is already on the wire, so a failed body write is unrecoverable.
	_, _ = io.WriteString(w, `{"error":"the data protection module is not configured on this server"}`)
	return false
}

// writeJSON renders through the injected writer.
func (s *Service) writeJSON(w http.ResponseWriter, status int, body any) {
	s.deps.WriteJSON(w, status, body)
}

// writeErr renders the surface's uniform error body.
func (s *Service) writeErr(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]any{"error": msg})
}

// writeMethodNotAllowed is the JSON-bodied 405 this surface uses. It is
// deliberately NOT the platform's plain-text methodNotAllowed: every other
// response on these routes is JSON, and a SPA that parses one and chokes on the
// other is a bug waiting for a bad day.
func (s *Service) writeMethodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	s.writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
}

// ── /api/system/backup ──────────────────────────────────────────────────────

// HandleConfig serves + updates the data-protection config (platform admin).
func (s *Service) HandleConfig(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.deps.Authz(w, r); !ok {
			return
		}
		cfg := s.config()
		s.writeJSON(w, http.StatusOK, map[string]any{
			"config": cfg,
			"status": s.BuildStatus(r.Context(), cfg),
		})
	case http.MethodPut:
		caller, ok := s.deps.Authz(w, r)
		if !ok {
			return
		}
		var req Config
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
			s.writeErr(w, http.StatusBadRequest, "bad body: "+err.Error())
			return
		}
		clean, err := sanitizeConfig(req)
		if err != nil {
			s.writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		// The snapshot-schedule intent is NOT client-settable: carry it forward
		// from the stored config so a backup-destination edit can never clear
		// (or forge) the record of who stopped the snapshot schedule and why.
		prev := s.config()
		clean.SnapshotScheduleDisabledAt = prev.SnapshotScheduleDisabledAt
		clean.SnapshotScheduleDisabledBy = prev.SnapshotScheduleDisabledBy
		clean.SnapshotScheduleDisabledReason = prev.SnapshotScheduleDisabledReason
		clean.SnapshotPolicyWrittenAt = prev.SnapshotPolicyWrittenAt
		// An OMITTED retain_count means "leave the stored retention alone", not
		// "clear it" — the same shape as the empty-secret PUT elsewhere in the
		// platform. A client that predates the field (or one that only wants to
		// change the destination) must not be able to silently drop an
		// operator's retention decision and hand the host applier back its own
		// fallback. Clearing is not an operation: 0 is a choice, and setting the
		// fallback explicitly is how you ask for the fallback.
		if clean.RetainCount == nil {
			clean.RetainCount = prev.RetainCount
		}
		clean.UpdatedBy = caller.Subject
		clean.UpdatedAt = s.now().UTC()
		putErr := s.putConfig(clean)
		// Audit BOTH outcomes (mirrors the snapshot-policy PUT): a platform-global
		// backup-posture change — enable/disable, destination, retention — must be
		// attributable, and a failed write that was never recorded is
		// indistinguishable from one that never happened. Destination is
		// security-relevant (data egress target), so remote_url is named.
		decision, status := "allow", http.StatusOK
		if putErr != nil {
			decision, status = "deny", http.StatusInternalServerError
		}
		s.deps.Audit.Record(r, AuditRecord{
			Actor: caller.Subject, Status: status, Decision: decision,
			Detail: map[string]any{
				"action":     "backup_config_update",
				"enabled":    clean.ScheduleEnabled,
				"remote_url": clean.RemoteURL,
				// Retention is a DATA-LOSS control (it is what prunes copies),
				// so the trail records the number, and records "unset" as the
				// distinct state it is rather than as a zero that would read as
				// "pruning off".
				"retain_count": auditRetain(clean.RetainCount),
			},
		})
		if putErr != nil {
			s.writeErr(w, http.StatusInternalServerError, putErr.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"config": clean,
			"status": s.BuildStatus(r.Context(), clean),
		})
	default:
		s.writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ── /api/system/backup/snapshots (the SM policy) ────────────────────────────

// HandlePolicy — GET/PUT the netops-daily snapshot policy.
// Platform-global config (§3a gate rule): the injected gate, audited writes.
func (s *Service) HandlePolicy(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.deps.Authz(w, r); !ok {
			return
		}
		s.writeJSON(w, http.StatusOK, s.PolicyView(r.Context()))
	case http.MethodPut:
		caller, ok := s.deps.Authz(w, r)
		if !ok {
			return
		}
		var upd snapshotPolicyUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&upd); err != nil {
			s.writeErr(w, http.StatusBadRequest, "bad body: "+err.Error())
			return
		}
		if upd.Enabled == nil && upd.ScheduleCron == nil && upd.RetentionMaxCount == nil && upd.RetentionMaxAgeDays == nil {
			s.writeErr(w, http.StatusBadRequest,
				"nothing to update — send enabled, schedule_cron, retention_max_count and/or retention_max_age_days")
			return
		}
		if (upd.ScheduleCron != nil && !validCron5(*upd.ScheduleCron)) ||
			(upd.RetentionMaxCount != nil && (*upd.RetentionMaxCount < 1 || *upd.RetentionMaxCount > 365)) ||
			(upd.RetentionMaxAgeDays != nil && (*upd.RetentionMaxAgeDays < 0 || *upd.RetentionMaxAgeDays > 3650)) {
			s.writeErr(w, http.StatusBadRequest, errBadSnapshotUpdate.Error())
			return
		}
		if upd.Reason != nil && (len(*upd.Reason) > snapshotNoteMax || hasControlChar(*upd.Reason)) {
			s.writeErr(w, http.StatusBadRequest,
				"reason must be at most 200 bytes and contain no control characters")
			return
		}
		err := s.smApplyUpdate(r.Context(), upd)
		// Record the operator INTENT alongside the cluster change. This is the
		// api half of the 2026-09-03 defect: the bootstrap must be able to ask
		// "did a human deliberately stop this?" instead of defaulting to true.
		// Only recorded on a SUCCESSFUL apply — storing an intent the cluster
		// rejected would make the two disagree in the other direction.
		if err == nil {
			if writeErr := s.recordSnapshotPolicyWrite(); writeErr != nil {
				s.deps.Log.Error("backup.snapshots", "could not record that this api wrote the snapshot policy — managed_by will misreport the last writer",
					map[string]any{"error": writeErr.Error()})
			}
		}
		if err == nil && upd.Enabled != nil {
			if intentErr := s.recordSnapshotScheduleIntent(*upd.Enabled, caller.Subject, upd.Reason); intentErr != nil {
				s.deps.Log.Error("backup.snapshots", "snapshot schedule intent could not be persisted — the bootstrap may re-enable a stopped policy",
					map[string]any{"error": intentErr.Error()})
			}
		}
		decision, status := "allow", http.StatusOK
		if err != nil {
			decision, status = "deny", http.StatusBadGateway
		}
		// Audit BOTH outcomes — a failed platform-config write that was never
		// recorded is indistinguishable from one that never happened.
		s.deps.Audit.Record(r, AuditRecord{
			Actor: caller.Subject, Status: status, Decision: decision,
			Detail: map[string]any{
				"action":  "snapshot_policy_update",
				"enabled": upd.Enabled, "schedule_cron": upd.ScheduleCron,
				"retention_max_count":    upd.RetentionMaxCount,
				"retention_max_age_days": upd.RetentionMaxAgeDays,
			},
		})
		if err != nil {
			s.writeErr(w, status, err.Error())
			return
		}
		s.writeJSON(w, http.StatusOK, s.PolicyView(r.Context()))
	default:
		s.writeMethodNotAllowed(w, "GET, PUT")
	}
}

// ── /api/system/backup/coverage ─────────────────────────────────────────────

// HandleCoverage serves the per-engine coverage table.
func (s *Service) HandleCoverage(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	if _, ok := s.deps.Authz(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w, "GET")
		return
	}
	s.writeJSON(w, http.StatusOK, s.BuildCoverage(r.Context()))
}

// ── /api/system/backup/snapshots/<verb> ─────────────────────────────────────

// HandleSnapshotOps dispatches /api/system/backup/snapshots/<verb>.
//
// The integrator's mux is a plain http.ServeMux: the EXACT pattern
// /api/system/backup/snapshots keeps serving the policy GET/PUT, and this
// subtree handler owns everything below it. An unknown verb is a 404, and a
// path with a further segment (…/list/extra) never matches a verb, so it 404s
// too — no prefix matching, no surprise routes.
func (s *Service) HandleSnapshotOps(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	// Gate FIRST, before the verb is even looked at: a tenant admin must not be
	// able to probe which verbs exist (§3a rule 3).
	caller, ok := s.deps.Authz(w, r)
	if !ok {
		return
	}
	verb := strings.TrimPrefix(r.URL.Path, "/api/system/backup/snapshots/")
	switch verb {
	case "list":
		if r.Method != http.MethodGet {
			s.writeMethodNotAllowed(w, "GET")
			return
		}
		s.handleSnapshotList(w, r)
	case "create", "delete", "restore", "verify":
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w, "POST")
			return
		}
		s.handleSnapshotAction(w, r, caller, verb)
	default:
		s.writeErr(w, http.StatusNotFound,
			"unknown snapshot action — expected list, create, delete, restore or verify")
	}
}

// handleSnapshotList renders the repository inventory.
func (s *Service) handleSnapshotList(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			s.writeErr(w, http.StatusBadRequest, "limit must be 1..200")
			return
		}
		limit = n
	}
	withSizes := r.URL.Query().Get("sizes") == "1"
	s.writeJSON(w, http.StatusOK, s.ListSnapshots(r.Context(), limit, withSizes))
}

// handleSnapshotAction validates SYNCHRONOUSLY, claims the single operation
// slot, and returns 202 with an Operation the caller polls. Every outcome —
// refusal and acceptance alike — is audited (§3a: a platform-global write that
// was never recorded is indistinguishable from one that never happened).
func (s *Service) handleSnapshotAction(w http.ResponseWriter, r *http.Request, caller Principal, verb string) {
	deny := func(status int, msg string, detail map[string]any) {
		detail["action"] = "snapshot_" + verb
		s.deps.Audit.Record(r, AuditRecord{
			Actor: caller.Subject, Status: status, Decision: "deny", Detail: detail,
		})
		s.writeErr(w, status, msg)
	}

	ctx := r.Context()
	var (
		kind    string
		timeout time.Duration
		target  OperationTarget
		body    func(ctx context.Context, progress func(string)) error
		audited = map[string]any{}

		// restorePlanned is the validated restore, carried past the switch so
		// its body can be built once the operation id exists.
		restorePlanned restorePlan
	)

	switch verb {
	case "create":
		var req snapshotCreateRequest
		if err := decodeSnapshotBody(w, r, &req); err != nil {
			deny(http.StatusBadRequest, "bad body: "+err.Error(), map[string]any{"reason": "bad_body"})
			return
		}
		note := strings.TrimSpace(req.Note)
		if len(note) > snapshotNoteMax {
			deny(http.StatusBadRequest, "note must be at most 200 bytes", map[string]any{"reason": "note_too_long"})
			return
		}
		if hasControlChar(note) {
			deny(http.StatusBadRequest, "note must not contain control characters", map[string]any{"reason": "note_control_char"})
			return
		}
		name, err := newManualSnapshotName(s.now())
		if err != nil {
			deny(http.StatusInternalServerError, "could not generate a snapshot name: "+err.Error(),
				map[string]any{"reason": "name_generation"})
			return
		}
		kind, timeout = OpKindSnapshotCreate, snapshotCreateTimeout
		target = OperationTarget{Snapshot: name}
		audited["snapshot"] = name
		audited["note"] = note
		body = func(ctx context.Context, progress func(string)) error {
			progress("taking snapshot " + name)
			payload, err := json.Marshal(map[string]any{
				// The api's OpenSearch role is scoped to netops-*; a manual
				// snapshot deliberately mirrors the SM policy's scope rather
				// than inventing a second one.
				"indices":              "netops-*",
				"include_global_state": false,
			})
			if err != nil {
				return err
			}
			return s.osDo(ctx, http.MethodPut,
				"/_snapshot/"+s.repo()+"/"+name+"?wait_for_completion=true",
				payload, nil, snapshotCreateTimeout)
		}

	case "delete":
		var req snapshotDeleteRequest
		if err := decodeSnapshotBody(w, r, &req); err != nil {
			deny(http.StatusBadRequest, "bad body: "+err.Error(), map[string]any{"reason": "bad_body"})
			return
		}
		name := strings.TrimSpace(req.Snapshot)
		if !snapshotNameRe.MatchString(name) {
			deny(http.StatusBadRequest, errBadSnapshotName.Error(), map[string]any{"reason": "bad_snapshot_name"})
			return
		}
		if req.Confirm != name {
			deny(http.StatusBadRequest,
				"confirm must equal the snapshot name exactly (type-to-confirm): deleting a restore point cannot be undone",
				map[string]any{"reason": "confirm_mismatch", "snapshot": name})
			return
		}
		if _, err := s.findSnapshot(ctx, name); err != nil {
			status := http.StatusBadGateway
			if isSnapshotNotFound(err) {
				status = http.StatusNotFound
			}
			deny(status, err.Error(), map[string]any{"reason": "snapshot_lookup", "snapshot": name})
			return
		}
		kind, timeout = OpKindSnapshotDelete, snapshotDeleteTimeout
		target = OperationTarget{Snapshot: name}
		audited["snapshot"] = name
		body = func(ctx context.Context, progress func(string)) error {
			progress("deleting snapshot " + name)
			return s.osDo(ctx, http.MethodDelete,
				"/_snapshot/"+s.repo()+"/"+name, nil, nil, snapshotDeleteTimeout)
		}

	case "restore":
		var req snapshotRestoreRequest
		if err := decodeSnapshotBody(w, r, &req); err != nil {
			deny(http.StatusBadRequest, "bad body: "+err.Error(), map[string]any{"reason": "bad_body"})
			return
		}
		plan, status, err := s.planRestore(ctx, req)
		if err != nil {
			deny(status, err.Error(), map[string]any{"reason": "restore_validation", "snapshot": strings.TrimSpace(req.Snapshot)})
			return
		}
		kind, timeout = OpKindSnapshotRestore, snapshotRestoreTimeout
		target = OperationTarget{
			Snapshot: plan.snapshot, Indices: plan.indices,
			Mode: plan.mode, RenamePrefix: plan.prefix,
		}
		audited["snapshot"] = plan.snapshot
		audited["mode"] = plan.mode
		audited["indices"] = plan.indices
		audited["rename_prefix"] = plan.prefix
		// Built after the slot is claimed (it records RestoredIndices onto the
		// Operation, so it needs the id).
		body = nil
		restorePlanned = plan

	case "verify":
		var req snapshotVerifyRequest
		if err := decodeSnapshotBody(w, r, &req); err != nil {
			deny(http.StatusBadRequest, "bad body: "+err.Error(), map[string]any{"reason": "bad_body"})
			return
		}
		name := strings.TrimSpace(req.Snapshot)
		if name != "" {
			if !snapshotNameRe.MatchString(name) {
				deny(http.StatusBadRequest, errBadSnapshotName.Error(), map[string]any{"reason": "bad_snapshot_name"})
				return
			}
			if _, err := s.findSnapshot(ctx, name); err != nil {
				status := http.StatusBadGateway
				if isSnapshotNotFound(err) {
					status = http.StatusNotFound
				}
				deny(status, err.Error(), map[string]any{"reason": "snapshot_lookup", "snapshot": name})
				return
			}
		}
		kind, timeout = OpKindSnapshotVerify, snapshotVerifyTimeout
		target = OperationTarget{Snapshot: name}
		audited["snapshot"] = name
		// The body is built AFTER the slot is claimed: the probe result rides
		// the Operation, so it needs the operation id.
		body = nil

	default:
		deny(http.StatusNotFound, "unknown snapshot action", map[string]any{"reason": "unknown_action"})
		return
	}

	op, conflict, ok := s.ops.begin(kind, caller.Subject, target)
	if !ok {
		if conflict == "" {
			deny(http.StatusInternalServerError, "could not register the operation", map[string]any{"reason": "operation_id"})
			return
		}
		audited["conflict_operation"] = conflict
		deny(http.StatusConflict,
			"another snapshot operation is already running ("+conflict+") — snapshot operations are serialised so two writers can never race the same repository",
			audited)
		return
	}
	if verb == "restore" {
		body = restorePlanned.run(s, op.ID)
	}
	if verb == "verify" {
		name := target.Snapshot
		id := op.ID
		body = func(ctx context.Context, progress func(string)) error {
			res, err := s.RunRestorabilityProbe(ctx, name, progress)
			s.recordProbeVerdict(res, err)
			verdict := res
			s.ops.update(id, func(o *Operation) {
				o.Verify = &verdict
				// A verify with no snapshot named probes the newest SUCCESS;
				// echo which one it actually chose, so a poller that never saw
				// the request can still say WHAT was proven.
				if o.Target.Snapshot == "" {
					o.Target.Snapshot = res.Snapshot
				}
			})
			if err != nil {
				return err
			}
			if !res.Match {
				return jsonError("restorability probe did NOT match: " + res.Detail)
			}
			return nil
		}
	}

	audited["action"] = "snapshot_" + verb
	audited["operation"] = op.ID
	s.deps.Audit.Record(r, AuditRecord{
		Actor: caller.Subject, Status: http.StatusAccepted, Decision: "allow", Detail: audited,
	})

	run := body
	if run == nil {
		// Unreachable: every verb above assigns a body. Guarded anyway, because
		// the failure mode of a nil body is an operation that sits in `running`
		// forever holding the slot — the one state this surface must never be
		// able to reach silently (§10).
		run = func(context.Context, func(string)) error {
			return jsonError("internal: no operation body was built for " + verb)
		}
	}
	s.deps.Go("snapshot-op-"+verb, func() { s.runOperation(op.ID, timeout, run) })
	s.writeJSON(w, http.StatusAccepted, map[string]any{"operation": op})
}

// decodeSnapshotBody reads a BOUNDED request body. An empty body is legal for
// create/verify, whose fields are all optional.
func decodeSnapshotBody(w http.ResponseWriter, r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

// ── /api/system/backup/operations ───────────────────────────────────────────

// operationsCapacityText keeps the prose and the constant from drifting apart.
const operationsCapacityText = "500"

const operationsRestartDetail = "the newest " + operationsCapacityText + " operations are persisted to SNAPSHOT_OPS_FILE and DO survive an api restart; an operation that was in flight when the process died is reported failed with its outcome stated as unknown, because a restart is not a completion. Older operations beyond the cap are gone"

// HandleOperations — GET /api/system/backup/operations.
func (s *Service) HandleOperations(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	if _, ok := s.deps.Authz(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w, "GET")
		return
	}
	s.writeJSON(w, http.StatusOK, OperationListView{
		Operations: s.ops.list(),
		Capacity:   OperationsCapacity,
		Detail:     operationsRestartDetail,
	})
}

// HandleOperationByID — GET /api/system/backup/operations/{id}.
func (s *Service) HandleOperationByID(w http.ResponseWriter, r *http.Request) {
	if !s.ready(w) {
		return
	}
	if _, ok := s.deps.Authz(w, r); !ok {
		return
	}
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w, "GET")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/system/backup/operations/")
	if !operationIDRe.MatchString(id) {
		s.writeErr(w, http.StatusNotFound, "no such operation")
		return
	}
	op, ok := s.ops.get(id)
	if !ok {
		s.writeErr(w, http.StatusNotFound, "no such operation — "+operationsRestartDetail)
		return
	}
	s.writeJSON(w, http.StatusOK, op)
}
