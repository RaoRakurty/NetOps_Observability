// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// promote.go — promoting a DERIVED experience incident into the platform
// incident record (tracker 255):
//
//	POST /api/dem/incidents/{id}/promote
//
// The gap this closes. `ExperienceIncident` has carried `incident_id` and
// `promoted` since slice 1 and the design of record (§M.2) says it IS an
// `internal/incident.Incident` with `source_type: "experience"` plus a DEM
// evidence packet — but nothing wrote one. Incidents were derived at read time
// and `incident.Repo.Ingest` was called only by the alert engine, so an
// experience incident could not be assigned, acknowledged, ticketed or
// resolved, and it vanished the moment its window rolled past.
//
// WHY AN OPERATOR ACTION RATHER THAN A SWEEPER. The row allows either. An
// explicit act was chosen because the derived list is deliberately generous —
// it raises an incident for every failing journey and every failing app in
// every window — and a sweeper over that is an incident storm with a human on
// the other end. Promotion says "this one is real", it is audited with the
// actor's name, and it is idempotent: the derived id is the dedup key, so a
// second promotion of the same window folds into the first incident and
// escalates its severity rather than raising a twin. A bounded sweeper can be
// added later ON TOP of this contract without changing it.
//
// WHAT IS AND IS NOT DUPLICATED. The incident system owns the LIFECYCLE
// (status, assignment, ticketing, resolution). This package owns the EVIDENCE.
// The promotion row stores the packet as it stood at the moment of the decision
// and nothing else — no status, no owner-assignment — because two owners for
// one lifecycle is how drift starts.

import (
	"errors"
	"net/http"
	"strings"

	"netops/backend/internal/dem"
	"netops/backend/internal/httppage"
)

// PromoteSuffix is the item route's sub-resource. The full literal is
// /api/dem/incidents/{id}/promote; the item handler owns the prefix.
const PromoteSuffix = "promote"

// promoteWire is the (optional) request body. There is NO tenant field and no
// incident id: the tenant comes from the token and the incident id comes from
// the platform, because a caller that could name either could file evidence
// against somebody else's incident.
type promoteWire struct {
	// Owner is the seam or team the operator is assigning it to. Optional; when
	// empty the incident inherits the seam owner the evidence already named,
	// which is a derived fact rather than a guess.
	Owner string `json:"owner,omitempty"`
	// Note is added to the incident's description. Bounded like every other
	// free-form field on this surface.
	Note string `json:"note,omitempty"`
}

// PromoteResponse is what the route answers.
type PromoteResponse struct {
	// IncidentID is the platform incident. Created reports whether THIS call
	// raised it: an operator who promotes twice is told it was already raised,
	// not shown a second incident.
	IncidentID string `json:"incident_id"`
	Created    bool   `json:"created"`
	// SourceType is stamped on the platform incident so the incident surfaces
	// can render the DEM evidence class. Returned so a caller never has to
	// assume it.
	SourceType string             `json:"source_type"`
	Promotion  Promotion          `json:"promotion"`
	Incident   ExperienceIncident `json:"incident"`
	Note       string             `json:"note"`
}

// handlePromote serves POST /api/dem/incidents/{id}/promote.
func (a *API) handlePromote(w http.ResponseWriter, r *http.Request, id string) {
	if err := httppage.RejectUnknownQuery(r, "window"); err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	// GateWrite, not GateRead: promotion RAISES something a human will be
	// paged about. The ingest gate is deliberately not accepted here — a
	// public RUM credential must never be able to raise an incident.
	tenant, p, ok := a.scoped(w, r, dem.GateWrite)
	if !ok {
		return
	}
	var body promoteWire
	if r.ContentLength > 0 {
		if !a.decode(w, r, &body, "promotion") {
			return
		}
	}
	asm, err := a.assemble(r, tenant, r.URL.Query().Get("window"))
	if err != nil {
		a.deps.WriteError(w, http.StatusBadRequest, err)
		return
	}
	var found *ExperienceIncident
	for i := range asm.Incidents {
		if asm.Incidents[i].ID == id {
			found = &asm.Incidents[i]
			break
		}
	}
	if found == nil {
		// A foreign tenant's id, or one whose window has rolled past, is
		// indistinguishable from absent. Never 403 — that would confirm the id.
		http.NotFound(w, r)
		return
	}
	// The backend check comes AFTER the id check, deliberately: an id that does
	// not belong to this tenant must answer 404 on EVERY deployment, so that
	// what a caller learns from probing an id never depends on which storage
	// backend the operator happens to run.
	if a.deps.Promoter == nil {
		// The incident system of record is Postgres-only. Saying so is the
		// honest answer; a 202 would claim an incident that does not exist.
		a.deps.WriteError(w, http.StatusConflict,
			errors.New("this deployment has no incident system of record (it is available on the Postgres backend), so an experience incident cannot be promoted; the derived view is unaffected"))
		return
	}

	// Already promoted? Return the SAME incident rather than raising a second.
	// This is checked before the write so a double-click costs one lookup.
	if prev, gerr := a.deps.Store.GetPromotion(r.Context(), tenant, id); gerr == nil {
		found.IncidentID, found.Promoted = prev.IncidentID, true
		a.deps.WriteJSON(w, http.StatusOK, PromoteResponse{
			IncidentID: prev.IncidentID, Created: false, SourceType: PromotionSource,
			Promotion: prev, Incident: *found,
			Note: "This experience incident was already promoted; the platform incident it belongs to is unchanged. The evidence packet stored with it is the one the promoting operator acted on — compare it with the live derivation on the incident view.",
		})
		return
	} else if !errors.Is(gerr, ErrNotFound) {
		a.deps.WriteError(w, http.StatusInternalServerError, gerr)
		return
	}

	owner := strings.TrimSpace(body.Owner)
	if owner == "" {
		owner = found.Owner // the seam owner the evidence already named
	}
	incidentID, created, perr := a.deps.Promoter.Promote(r.Context(), PromotionInput{
		TenantID: tenant, // from the TOKEN, never the body
		// One value, two jobs: source_id records what this incident came FROM,
		// dedup_key makes a re-promotion fold into the same incident.
		SourceID: id, DedupKey: id,
		Title:       found.Title,
		Description: promoteDescription(*found, body.Note),
		Severity:    found.Severity,
		Owner:       clip(owner, MaxLabelBytes),
		Actor:       p.Subject,
	})
	if perr != nil {
		a.deps.Counters.PromotionErrors.Add(1)
		a.deps.LogWarn("an experience incident could not be promoted into the incident record",
			map[string]any{"err": perr.Error(), "experience_id": id})
		a.deps.WriteError(w, http.StatusInternalServerError, perr)
		return
	}

	packet := *found
	packet.IncidentID, packet.Promoted = incidentID, true
	stored, serr := a.deps.Store.SavePromotion(r.Context(), Promotion{
		TenantID: tenant, ExperienceID: id, IncidentID: incidentID,
		PromotedAt: a.deps.Now().UTC(), PromotedBy: p.Subject, Packet: packet,
	})
	if serr != nil {
		// The incident EXISTS at this point — the platform record was written
		// before the packet. Say exactly that rather than implying nothing
		// happened: an operator who retries must know they are not raising a
		// second incident (the dedup key guarantees they are not).
		a.deps.Counters.PromotionErrors.Add(1)
		a.deps.LogWarn("an experience incident was promoted but its evidence packet could not be stored",
			map[string]any{"err": serr.Error(), "experience_id": id, "incident_id": incidentID})
		a.deps.WriteError(w, http.StatusInternalServerError,
			errors.New("incident "+incidentID+" was raised, but its evidence packet could not be stored: "+serr.Error()+
				". Retrying is safe — it will fold into the same incident, not raise a second."))
		return
	}
	a.deps.Counters.IncidentsPromoted.Add(1)
	status := http.StatusCreated
	note := "Raised as a platform incident with the experience evidence class. Its lifecycle — assignment, acknowledgement, ticketing, resolution — now lives in the incident record; the evidence stays here and the two are compared on every read."
	if !created {
		status = http.StatusOK
		note = "Folded into the platform incident already open for this window (the derived incident id is the dedup key), and its severity escalated if this evidence is worse. No second incident was raised."
	}
	a.deps.WriteJSON(w, status, PromoteResponse{
		IncidentID: incidentID, Created: created, SourceType: PromotionSource,
		Promotion: stored, Incident: packet, Note: note,
	})
}

// promoteDescription writes the incident's description from the evidence, so
// the incident record is readable on its own — an operator looking at the
// incident list must not have to open a second product to learn what happened.
func promoteDescription(inc ExperienceIncident, note string) string {
	b := &strings.Builder{}
	b.WriteString(inc.Title)
	if inc.LeadingHypothesisID != "" && len(inc.Hypotheses) > 0 {
		for _, h := range inc.Hypotheses {
			if h.ID != inc.LeadingHypothesisID {
				continue
			}
			b.WriteString(". Leading cause: ")
			b.WriteString(h.Explanation)
			b.WriteString(" (")
			b.WriteString(inc.VerdictTier)
			b.WriteString(")")
			break
		}
	}
	if inc.Seam != "" {
		b.WriteString(". Failing seam: ")
		b.WriteString(inc.Seam)
	}
	if len(inc.MissingEvidence) > 0 {
		// The gaps travel with the claim. An incident description that lists
		// only what we saw invites the reader to assume we looked everywhere.
		b.WriteString(". Not measured: ")
		names := make([]string, 0, len(inc.MissingEvidence))
		for _, m := range inc.MissingEvidence {
			names = append(names, m.Source)
		}
		b.WriteString(strings.Join(names, ", "))
	}
	if strings.TrimSpace(note) != "" {
		b.WriteString(". Operator note: ")
		b.WriteString(strings.TrimSpace(note))
	}
	return clip(b.String(), MaxDetailBytes)
}
