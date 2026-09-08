// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_routing_http.go — the HTTP surface over the tenant's TAC ROUTING
// record, built the same way the connector-settings surface is
// (caseconn_http.go): an injectable module with fail-closed deps, so the root
// package holds one line per route and no decision at all.
//
// WHY IT IS ITS OWN MODULE rather than a handler in the api's adapter block.
// The rule the TAC adapter is held to (tac_markers_test.go) is that decisions
// live in a package and the api only resolves the caller and renders. Everything
// here IS a decision — which connectors a vendor may be routed to, which
// dialects a capture may be preferred for, what a save is allowed to name, when
// a record is empty enough to delete — and none of it needs anything from the
// api except the caller's resolved scope.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/tac"
)

// tacRoutingMaxBody bounds a routing save. The largest legitimate record is a
// contract table with per-serial overrides; 256 KiB is far above it and far
// below a DoS (§9).
const tacRoutingMaxBody = 256 << 10

// TACRoutingAPIDeps are the surface's injected collaborators. Every one is
// required: a surface built from incomplete deps could read or write unscoped,
// so the constructor fails closed rather than defaulting a gap.
type TACRoutingAPIDeps struct {
	// Authz authorizes the caller and returns the resolved principal. It has
	// already written the error response when ok is false. It is the SAME gate
	// the connector-settings surface uses, because this is the same class of
	// data: one tenant's own commercial relationship with a vendor.
	Authz func(w http.ResponseWriter, r *http.Request, gate ConnectorGate) (ConnectorPrincipal, bool)
	// Store resolves the routing store at REQUEST time — a function rather than
	// a value because the store is built after the routes are registered.
	Store func() *TACRoutingStore
	// Connectors lists what this tenant could route to, so a save can refuse a
	// connector this platform does not have and a GET can offer the real choices.
	Connectors func(ctx context.Context, tenant string) []tac.ConnectorInfo
	// Dialects lists the platforms a preferred capture may be set for.
	Dialects func() []RoutingDialect
	// Audit records every write, on both outcomes.
	Audit CaseAuditSink
	// WriteJSON / WriteError are the platform's response writers.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)
	// Now is the clock.
	Now func() time.Time
}

// RoutingDialect is one CLI dialect a preferred capture may be set for.
type RoutingDialect struct {
	Dialect string `json:"dialect"`
	Display string `json:"display"`
}

func (d TACRoutingAPIDeps) validate() error {
	missing := make([]string, 0, 8)
	check := func(n string, ok bool) {
		if !ok {
			missing = append(missing, n)
		}
	}
	check("Authz", d.Authz != nil)
	check("Store", d.Store != nil)
	check("Connectors", d.Connectors != nil)
	check("Dialects", d.Dialects != nil)
	check("Audit", d.Audit != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("Now", d.Now != nil)
	if len(missing) > 0 {
		return fmt.Errorf("ticketing: TACRoutingAPIDeps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// TACRoutingAPI is the routing-settings surface.
type TACRoutingAPI struct{ deps TACRoutingAPIDeps }

// NewTACRoutingAPI builds it, failing CLOSED on incomplete deps.
func NewTACRoutingAPI(d TACRoutingAPIDeps) (*TACRoutingAPI, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &TACRoutingAPI{deps: d}, nil
}

// RoutingView is the record plus the choices a screen needs to edit it.
type RoutingView struct {
	Routing TACRoutingConfig `json:"routing"`
	// Configured says whether this tenant has a stored record at all. It is a
	// separate field from an empty record because the two mean different things
	// to the screen: "nothing set yet, here is what you could set" versus "you
	// cleared it".
	Configured bool                `json:"configured"`
	Connectors []tac.ConnectorInfo `json:"connectors,omitempty"`
	Dialects   []RoutingDialect    `json:"dialects,omitempty"`
}

// HandleRouting serves GET/PUT/DELETE on the caller's own routing record.
func (a *TACRoutingAPI) HandleRouting(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		http.NotFound(w, r)
		return
	}
	gate := ConnectorGateRead
	if r.Method == http.MethodPut || r.Method == http.MethodDelete {
		gate = ConnectorGateWrite
	}
	p, ok := a.deps.Authz(w, r, gate)
	if !ok {
		return
	}
	store := a.deps.Store()
	if store == nil {
		a.deps.WriteError(w, http.StatusServiceUnavailable,
			errors.New("TAC routing settings are not available on this build"))
		return
	}
	// A NON-CROSS caller's as_tenant is IGNORED outright; a cross-tenant caller
	// may narrow. The token is the only source of ownership (§3a.2).
	target := ResolveTACTenant(p.Tenant, p.Cross, r.URL.Query().Get("as_tenant"))

	switch r.Method {
	case http.MethodGet:
		cfg, found, err := store.Get(p.Tenant, p.Cross, target)
		if err != nil {
			http.NotFound(w, r) // another tenant's row is never confirmed to exist
			return
		}
		a.deps.WriteJSON(w, http.StatusOK, RoutingView{
			Routing: cfg, Configured: found,
			Connectors: a.deps.Connectors(r.Context(), p.Tenant),
			Dialects:   a.deps.Dialects(),
		})
	case http.MethodPut:
		var in TACRoutingConfig
		if !a.decode(w, r, &in) {
			return
		}
		saved, err := store.Set(p.Tenant, p.Cross, target, in, a.knownConnector(r.Context(), p.Tenant))
		if err != nil {
			if errors.Is(err, ErrTenantNotFound) {
				http.NotFound(w, r)
				return
			}
			a.audit(p, "routing.save", "refused", err.Error())
			a.deps.WriteError(w, http.StatusBadRequest, err)
			return
		}
		a.audit(p, "routing.save", "ok", fmt.Sprintf("routes=%d contracts=%d overrides=%d captures=%d",
			len(saved.RouteByVendor), len(saved.ContractByVendor),
			len(saved.ContractBySerial), len(saved.CaptureByDialect)))
		a.deps.WriteJSON(w, http.StatusOK, RoutingView{Routing: saved, Configured: !saved.IsEmpty()})
	case http.MethodDelete:
		if err := store.Delete(p.Tenant, p.Cross, target); err != nil {
			http.NotFound(w, r)
			return
		}
		a.audit(p, "routing.delete", "ok", "")
		w.WriteHeader(http.StatusNoContent)
	default:
		a.deps.WriteError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// knownConnector answers "does this platform have a connector with this id", so
// a route cannot be saved pointing at nothing.
func (a *TACRoutingAPI) knownConnector(ctx context.Context, tenant string) func(string) bool {
	ids := map[string]bool{}
	for _, in := range a.deps.Connectors(ctx, tenant) {
		ids[in.ID] = true
	}
	return func(id string) bool { return ids[id] }
}

// decode reads a bounded, unknown-field-rejecting body. An unknown field is a
// 400 rather than a silently ignored one, which is what makes "the owner is
// stamped from the token" checkable: a `tenant_id` in the body is refused.
func (a *TACRoutingAPI) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, tacRoutingMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		a.deps.WriteError(w, http.StatusBadRequest, fmt.Errorf("bad body: %w", err))
		return false
	}
	return true
}

func (a *TACRoutingAPI) audit(p ConnectorPrincipal, action, result, detail string) {
	a.deps.Audit.RecordCaseAction(CaseAuditEvent{
		At: a.deps.Now(), TenantID: p.Tenant, Actor: p.Subject,
		Action: action, Result: result, Detail: detail,
	})
}
