// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ifgroup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ── injected collaborators (§5: no ambient authority) ───────────────────────

// Gate is the permission a route needs. This package states WHAT; the
// integrator maps it onto the RBAC model. The only route here is a READ.
type Gate int

// GateRead is per-tenant operator read access.
const GateRead Gate = 0

// Principal is the caller's already-authorized scope.
type Principal struct {
	Tenant  string
	Cross   bool
	Subject string
}

// Device is the inventory row this module needs. Vendor drives the dialect;
// Name is carried because the two collector lanes label series differently
// (`device` is the device id on the SNMP lane and the target name on the gNMI
// lane, after gnmic renames `source` → `device`).
type Device struct {
	ID       string
	Name     string
	Vendor   string
	TenantID string
}

// Sample is one VictoriaMetrics instant-query result row.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// Deps are the module's injected collaborators. New refuses an incomplete Deps
// rather than returning a handler that could read unscoped.
type Deps struct {
	// NOTE: this module deliberately has NO clock collaborator. It reads only
	// instant queries, and the one time value it handles — the rate window — is
	// a caller-supplied duration validated against fixed bounds, never a
	// wall-clock comparison. A Deps field nothing calls is dead weight that
	// invites a reviewer to look for a time dependency that does not exist.

	// Authz authorizes the caller at the given gate and returns the resolved
	// principal. It has already written the error response when ok is false.
	// Required.
	Authz func(w http.ResponseWriter, r *http.Request, gate Gate) (Principal, bool)

	// LookupDevice resolves one device id from the inventory. ok=false means
	// "no such device"; the handler renders that identically to a foreign id.
	// Required.
	LookupDevice func(deviceID string) (Device, bool)

	// CanSee reports whether the principal may see the device — the §3a rule-1
	// boundary, which this module refuses to guess. Required.
	CanSee func(d Device, p Principal) bool

	// ScopeFilters returns the caller's VictoriaMetrics `extra_filters[]` device
	// boundary. It returns nil ONLY for an unrestricted cross-tenant principal;
	// a scoped principal ALWAYS gets at least one matcher (the no-visible-device
	// sentinel). Required.
	ScopeFilters func(r *http.Request, p Principal) []string

	// VMQuery runs one VictoriaMetrics instant query with the given
	// extra_filters[]. Required.
	VMQuery func(ctx context.Context, query string, filters []string) ([]Sample, error)

	// VRFTerm returns the device vendor's own word for the VRF concept and
	// whether a vendor profile actually CLAIMS that vendor. known=false means
	// the returned word is the industry-majority display default, not an
	// identification of the device. Required.
	VRFTerm func(vendor string) (term string, known bool)

	// WriteJSON / WriteError are the platform's response writers. Required.
	WriteJSON  func(w http.ResponseWriter, status int, body any)
	WriteError func(w http.ResponseWriter, status int, err error)

	// LogWarn is the structured logger (§10). Required.
	LogWarn func(msg string, fields map[string]any)
}

func (d Deps) validate() error {
	missing := make([]string, 0, 9)
	check := func(name string, ok bool) {
		if !ok {
			missing = append(missing, name)
		}
	}
	check("Authz", d.Authz != nil)
	check("LookupDevice", d.LookupDevice != nil)
	check("CanSee", d.CanSee != nil)
	check("ScopeFilters", d.ScopeFilters != nil)
	check("VMQuery", d.VMQuery != nil)
	check("VRFTerm", d.VRFTerm != nil)
	check("WriteJSON", d.WriteJSON != nil)
	check("WriteError", d.WriteError != nil)
	check("LogWarn", d.LogWarn != nil)
	if len(missing) > 0 {
		return fmt.Errorf("ifgroup: Deps missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

// API is the module's HTTP surface.
type API struct{ deps Deps }

// New builds the API over the injected Deps, failing CLOSED on an incomplete
// Deps rather than returning a handler set that silently reads unscoped.
func New(d Deps) (*API, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &API{deps: d}, nil
}

// errScopeless is the fail-closed condition: a scoped principal reached a
// VictoriaMetrics read with no device boundary to attach. That is a wiring bug,
// never a reason to read the fleet.
var errScopeless = errors.New("ifgroup: scoped principal has no metrics device filter")
