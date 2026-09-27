// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package changeledger holds the change ledger's PRODUCERS (Iris plan N-D2) and
// its actor normalization (N-D4). The ledger itself — the persisted
// dem_change_events table and its file twin — is internal/dem/experience; this
// package turns facts other modules already hold (a configuration capture that
// found a new version, an allowed mutation through this platform) into
// normalized, idempotent ChangeEvents and writes them there.
//
// It imports no other domain: the composition root adapts each producer's
// source (configstore, the audit middleware, the identity store) into this
// package's own small input types, so deleting a producer touches nothing but
// its wiring (CLAUDE.md §2, §4).
package changeledger

import (
	"strings"

	"netops/backend/internal/dem/experience"
)

// Person is what the canonical identity store (tracker 300) knows about one
// Correlix principal.
type Person struct {
	ID       string
	Display  string
	TenantID string
}

// Directory is the read-only slice of the canonical identity store actor
// normalization needs. An implementation must resolve EXACTLY — no fuzzy match,
// no username-to-person inference — because a wrong match silently attributes a
// change to the wrong person, which is worse than an unresolved actor.
type Directory interface {
	// PrincipalByID resolves a Correlix principal id (the JWT `sub`, the audit
	// actor). ok=false means the store does not know it.
	PrincipalByID(id string) (Person, bool)
}

// SourceActor is an actor as a producer's source reported it.
type SourceActor struct {
	// Tenant is the tenant the change belongs to. A principal is resolved only
	// inside it.
	Tenant string
	// Raw is the actor exactly as the source reported it.
	Raw string
	// IsPrincipalID is true only when the SOURCE vouches that Raw is a Correlix
	// principal id — the audit trail and a manual capture's trigger do; a
	// device's syslog user or a controller's admin name do not, and are never
	// looked up (a device account called "admin" is not the Correlix user
	// "admin").
	IsPrincipalID bool
	// TypeHint is the actor type the source can vouch for when the actor is not
	// resolved (a scheduler knows it is the system). "" means it cannot.
	TypeHint string
}

// Actor is the normalized actor a ChangeEvent carries.
type Actor struct {
	Source    string // → ChangeEvent.Actor: the source identity, verbatim
	Type      string // → ChangeEvent.ActorType
	ID        string // → ChangeEvent.ActorID: canonical when resolved, else Source
	Display   string // → ChangeEvent.ActorDisplay
	Canonical bool   // the identity store vouched for ID
}

// NormalizeActor maps a source actor onto a Correlix identity where the
// canonical identity store knows it, and otherwise keeps the source identity
// verbatim. It NEVER guesses:
//
//   - an empty actor stays empty, type unknown;
//   - only an actor the source vouches is a principal id is looked up, and only
//     by exact id;
//   - a principal that exists in ANOTHER tenant is withheld (type user, no id):
//     naming it would put a platform operator's or another tenant's identity
//     into this tenant's ledger, which the audit feed already refuses to do;
//   - an unknown principal id is kept verbatim — it is this tenant's own
//     history (a deleted account), not a guess;
//   - an actor that is not a principal id is kept verbatim with the source's
//     type hint, or unknown.
func NormalizeActor(dir Directory, in SourceActor) Actor {
	raw := strings.TrimSpace(in.Raw)
	hint := strings.ToLower(strings.TrimSpace(in.TypeHint))
	if !experience.ValidChangeActorType(hint) {
		hint = experience.ChangeActorUnknown
	}
	if raw == "" {
		return Actor{Type: experience.ChangeActorUnknown}
	}
	if in.IsPrincipalID && dir != nil {
		if p, ok := dir.PrincipalByID(raw); ok {
			if !sameTenant(p.TenantID, in.Tenant) {
				return Actor{Type: experience.ChangeActorUser}
			}
			id := strings.TrimSpace(p.ID)
			if id == "" {
				id = raw
			}
			return Actor{Source: raw, Type: experience.ChangeActorUser, ID: id,
				Display: strings.TrimSpace(p.Display), Canonical: true}
		}
		// A principal id the store does not know: an authenticated caller
		// whose account has since gone. Kept verbatim; it was a user.
		return Actor{Source: raw, Type: experience.ChangeActorUser, ID: raw}
	}
	return Actor{Source: raw, Type: hint, ID: raw}
}

func sameTenant(a, b string) bool {
	x, y := strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	return x != "" && x == y
}
