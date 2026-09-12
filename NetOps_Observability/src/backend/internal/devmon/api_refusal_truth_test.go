// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devmon_test

// api_refusal_truth_test.go — the audit trail must record what happened
// (3.9-08).
//
// THE DEFECT. Every SetMonitoring failure was audited as a 402 LICENCE DENIAL
// before anything classified it:
//
//	a.audit(r, caller, http.StatusPaymentRequired, "deny", …)
//	if a.d.Refusal != nil && a.d.Refusal(w, err) { return }
//	if errors.Is(err, ErrUnknownDevice) { http.NotFound(w, r); return }
//	a.d.WriteError(w, http.StatusConflict, err)
//
// So a store that could not persist the decision, and a device deleted between
// the visibility check and the write, both went into the record of record as
// ceiling refusals that never occurred — and the storage failure was answered
// 409, as though the platform had declined a request rather than failed to
// serve it. The audit trail is the evidence an operator reaches for when the
// licence question is asked; a fabricated reason in it is a correctness defect,
// not a cosmetic one.

import (
	"errors"
	"net/http"
	"testing"

	"netops/backend/internal/devmon"
)

// errLicenceCeiling stands for the ceiling refusal the platform's renderer recognises.
var errLicenceCeiling = errors.New("monitored-device ceiling reached")

// auditingHarness wires an Audit sink and a Refusal renderer that recognises
// ONLY errLicenceCeiling — the production shape (entitlement.WriteRefusal returns
// false for anything that is not a licence error).
func auditingHarness(t *testing.T) (*harness, *[]devmon.AuditRecord) {
	t.Helper()
	var events []devmon.AuditRecord
	h := newHarness(t, func(d *devmon.Deps) {
		d.Audit = func(_ *http.Request, ev devmon.AuditRecord) { events = append(events, ev) }
		d.Refusal = func(w http.ResponseWriter, err error) bool {
			if !errors.Is(err, errLicenceCeiling) {
				return false
			}
			w.WriteHeader(http.StatusPaymentRequired)
			return true
		}
	})
	return h, &events
}

func TestAStorageFailureIsNotAuditedAsALicenceDenial(t *testing.T) {
	h, events := auditingHarness(t)
	h.reg.setErr = errors.New("persist monitoring decision: disk full")

	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)

	if w.Code == http.StatusPaymentRequired {
		t.Fatalf("a storage failure was answered 402 — the operator is told the LICENCE refused them "+
			"for a write the server simply could not do: %s", w.Body.String())
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 — the renderer declined this error, so it is not a refusal at "+
			"all; it is the write failing", w.Code)
	}
	if len(*events) != 1 {
		t.Fatalf("audited %d events, want exactly 1", len(*events))
	}
	ev := (*events)[0]
	if ev.Status == http.StatusPaymentRequired {
		t.Fatalf("THE AUDIT TRAIL CLAIMS A LICENCE CEILING THAT NEVER HAPPENED: %+v. A storage failure "+
			"must never be written into the record of record as a 402 ceiling refusal.", ev)
	}
	if ev.Status != http.StatusInternalServerError {
		t.Errorf("audited status = %d, want the 500 the caller actually got", ev.Status)
	}
	if ev.Detail["refusal"] == "licence_ceiling" {
		t.Errorf("the audit detail names a licence ceiling: %+v", ev.Detail)
	}
	if ev.Decision == "allow" {
		t.Errorf("a failed write must not be audited as an allow: %+v", ev)
	}
}

func TestAConcurrentlyDeletedDeviceIsNotAuditedAsALicenceDenial(t *testing.T) {
	h, events := auditingHarness(t)
	// Visible at resolve time, gone by the time the registry is asked to write.
	h.reg.setErr = devmon.ErrUnknownDevice

	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 — a device that vanished is not a ceiling refusal", w.Code)
	}
	if len(*events) != 1 {
		t.Fatalf("audited %d events, want exactly 1", len(*events))
	}
	ev := (*events)[0]
	if ev.Status == http.StatusPaymentRequired {
		t.Fatalf("a concurrently-deleted device was audited as a LICENCE DENIAL: %+v", ev)
	}
	if ev.Status != http.StatusNotFound {
		t.Errorf("audited status = %d, want the 404 the caller got", ev.Status)
	}
	if ev.Detail["refusal"] == "licence_ceiling" {
		t.Errorf("the audit detail names a licence ceiling: %+v", ev.Detail)
	}
}

// The genuine article must be unchanged: a real ceiling refusal is still a 402,
// still audited as a deny, and still says so.
func TestAGenuineCeilingRefusalIsStillAuditedAsOne(t *testing.T) {
	h, events := auditingHarness(t)
	h.reg.setErr = errLicenceCeiling

	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want the platform's 402", w.Code)
	}
	if len(*events) != 1 {
		t.Fatalf("audited %d events, want exactly 1", len(*events))
	}
	ev := (*events)[0]
	if ev.Status != http.StatusPaymentRequired || ev.Decision != "deny" {
		t.Fatalf("a real ceiling refusal must still be audited as a 402 deny: %+v", ev)
	}
	if ev.Detail["refusal"] != "licence_ceiling" {
		t.Errorf("the audit detail does not name the ceiling: %+v", ev.Detail)
	}
	if ev.Detail["device"] != "d1" || ev.Detail["action"] != "device_monitoring_set" {
		t.Errorf("the event must still name the action and the device: %+v", ev.Detail)
	}
}

// With NO renderer wired (a build with no licence subsystem at all) the module
// cannot tell a ceiling from a failed write. It must keep the documented 4xx
// and say it does not know, rather than assert a reason it cannot have.
func TestWithNoRendererTheRefusalIsRecordedAsUnclassified(t *testing.T) {
	var events []devmon.AuditRecord
	h := newHarness(t, func(d *devmon.Deps) {
		d.Audit = func(_ *http.Request, ev devmon.AuditRecord) { events = append(events, ev) }
		d.Refusal = nil
	})
	h.reg.setErr = errLicenceCeiling

	w := h.do(http.MethodPut, "/api/devices/d1/monitoring", `{"enabled":true}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want the documented 409 fallback", w.Code)
	}
	if len(events) != 1 {
		t.Fatalf("audited %d events, want exactly 1", len(events))
	}
	if events[0].Status != http.StatusConflict {
		t.Errorf("audited status = %d, want the 409 the caller got", events[0].Status)
	}
	if events[0].Detail["refusal"] != "unclassified" {
		t.Errorf("an unclassifiable refusal must say so: %+v", events[0].Detail)
	}
}
