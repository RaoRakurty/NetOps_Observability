// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package policy

// catalog.go defines the immutable, built-in catalog of security-policy
// controls. Each entry is a self-describing Setting: it carries everything the
// UI needs to render a card (label, rationale, NIST reference, tier) and
// everything the engine needs to validate + resolve (kind, default, constraint,
// lock/harden semantics). The catalog is the single source of truth for *what*
// can be configured; Documents (per scope) only ever carry *overrides* of these
// keys. An override whose key is not in the catalog is meaningless and rejected.

import "slices"

// time helpers — every time span in the catalog is stored as whole seconds in
// Value.Num (KindDuration). Constraint.Unit records the *display* granularity so
// the UI can render "30 minutes" / "90 days" without changing the stored unit.
func secs(n int64) int64  { return n }
func mins(n int64) int64  { return n * 60 }
func hours(n int64) int64 { return n * 3600 }
func days(n int64) int64  { return n * 86400 }

// typed Value constructors keep the catalog declarations terse and prevent
// Kind/field mismatches (e.g. setting Bool on a KindInt).
func boolV(b bool) Value       { return Value{Kind: KindBool, Bool: b} }
func intV(n int64) Value       { return Value{Kind: KindInt, Num: n} }
func durV(secs int64) Value    { return Value{Kind: KindDuration, Num: secs} }
func listV(xs ...string) Value { return Value{Kind: KindList, List: xs} }

func ptr(n int64) *int64 { return &n }

// Catalog is an ordered, indexed collection of Settings. It is immutable after
// construction; BuiltinCatalog returns the platform's baseline.
type Catalog struct {
	settings []Setting
	byKey    map[string]Setting
}

// newCatalog indexes a slice of settings by key. Panics on a duplicate key —
// that is a programming error in the static catalog, caught at startup.
func newCatalog(settings []Setting) *Catalog {
	byKey := make(map[string]Setting, len(settings))
	for _, s := range settings {
		if _, dup := byKey[s.Key]; dup {
			panic("policy: duplicate catalog key " + s.Key)
		}
		byKey[s.Key] = s
	}
	return &Catalog{settings: settings, byKey: byKey}
}

// Setting returns the catalog definition for a key.
func (c *Catalog) Setting(key string) (Setting, bool) {
	s, ok := c.byKey[key]
	return s, ok
}

// All returns every setting in catalog order (stable: grouped by domain).
func (c *Catalog) All() []Setting { return slices.Clone(c.settings) }

// Domain returns the settings belonging to one control family, in catalog order.
func (c *Catalog) Domain(d Domain) []Setting {
	var out []Setting
	for _, s := range c.settings {
		if s.Domain == d {
			out = append(out, s)
		}
	}
	return out
}

// Keys returns every catalog key (for validation that an override is known).
func (c *Catalog) Keys() []string {
	out := make([]string, len(c.settings))
	for i, s := range c.settings {
		out[i] = s.Key
	}
	return out
}

// BuiltinCatalog is the platform's NIST-aligned baseline. Defaults are the
// catalog floor used when no scope overrides a setting. Harden directions encode
// the monotonic "a more specific scope may only tighten" rule:
//   - HardenHigher: stricter = larger value, or true for bools (e.g. min length,
//     require MFA) — a lower scope can raise the floor, never lower it.
//   - HardenLower:  stricter = smaller value (e.g. idle timeout, token TTL) — a
//     lower scope can shorten, never lengthen.
//   - HardenNone:   freely overridable within Constraint (used where a "0 =
//     disabled/unlimited" sentinel makes monotonicity ambiguous).
func BuiltinCatalog() *Catalog {
	return newCatalog([]Setting{
		// ---- Authentication (SP 800-63B AAL / §4–5) -----------------------
		{
			Key: "authentication.mfa_required", Domain: DomainAuthentication,
			Label:       "Require multi-factor authentication",
			Description: "Force a second authentication factor for interactive logins.",
			Kind:        KindBool, Default: boolV(false), Tier: TierBasic,
			NIST: []string{"SP 800-63B §4.3 (AAL2)"}, Lockable: true, Harden: HardenHigher,
			Rationale: "MFA is the single highest-leverage control against credential theft; once required at a scope it cannot be relaxed below.",
		},
		{
			Key: "authentication.allowed_methods", Domain: DomainAuthentication,
			Label:       "Allowed authentication methods",
			Description: "Which login mechanisms are permitted for this scope.",
			Kind:        KindList, Default: listV("password"), Tier: TierAdvanced,
			Constraint: Constraint{Enum: []string{"password", "oidc", "saml", "ldap", "tacacs", "passkey"}},
			NIST:       []string{"SP 800-63B §5"}, Harden: HardenNone,
			Rationale: "Restricting accepted methods narrows the authentication attack surface.",
		},
		{
			Key: "authentication.idp_only", Domain: DomainAuthentication,
			Label:       "Federated identity only",
			Description: "Disallow local password login; require an external IdP.",
			Kind:        KindBool, Default: boolV(false), Tier: TierAdvanced,
			NIST: []string{"SP 800-63B §5.1"}, Lockable: true, Harden: HardenHigher,
			Rationale: "Centralising authentication at the IdP removes local credential stores as a target.",
		},
		{
			Key: "authentication.reauth_interval", Domain: DomainAuthentication,
			Label:       "Re-authentication interval",
			Description: "Maximum time before a fresh authentication is required for sensitive actions.",
			Kind:        KindDuration, Default: durV(hours(12)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(mins(5)), Max: ptr(hours(24)), Unit: "hours"},
			NIST:       []string{"SP 800-63B §5.2.11"}, Harden: HardenLower,
			Rationale: "Periodic re-authentication bounds the value of a hijacked session.",
		},

		// ---- Password (SP 800-63B §5.1.1 / SP 800-53 IA-5) ----------------
		{
			Key: "password.min_length", Domain: DomainPassword,
			Label:       "Minimum password length",
			Description: "Shortest permitted password, in characters.",
			Kind:        KindInt, Default: intV(12), Tier: TierBasic,
			Constraint: Constraint{Min: ptr(8), Max: ptr(128), Unit: "characters"},
			NIST:       []string{"SP 800-63B §5.1.1.2"}, Lockable: true, Harden: HardenHigher,
			Rationale: "Length is the dominant factor in password strength; the floor can be raised per scope but never lowered.",
		},
		{
			Key: "password.complexity_classes", Domain: DomainPassword,
			Label:       "Required character classes",
			Description: "Minimum distinct classes (lower, upper, digit, symbol) a password must include.",
			Kind:        KindInt, Default: intV(0), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(0), Max: ptr(4), Unit: "classes"},
			NIST:       []string{"SP 800-63B §5.1.1.2"}, Harden: HardenHigher,
			Rationale: "NIST de-emphasises composition rules in favour of length + breach checks; provided for environments with external mandates, default off.",
		},
		{
			Key: "password.history_depth", Domain: DomainPassword,
			Label:       "Password history depth",
			Description: "Number of previous passwords that may not be reused.",
			Kind:        KindInt, Default: intV(5), Tier: TierBasic,
			Constraint: Constraint{Min: ptr(0), Max: ptr(24), Unit: "passwords"},
			NIST:       []string{"SP 800-53 IA-5(1)"}, Harden: HardenHigher,
			Rationale: "Reuse prevention limits the blast radius of an exposed credential.",
		},
		{
			Key: "password.breach_check", Domain: DomainPassword,
			Label:       "Block known-breached passwords",
			Description: "Reject passwords found in compromised-credential corpora.",
			Kind:        KindBool, Default: boolV(true), Tier: TierBasic,
			NIST: []string{"SP 800-63B §5.1.1.2"}, Harden: HardenHigher,
			Rationale: "Screening against breach lists is the NIST-recommended replacement for arbitrary complexity rules.",
		},
		{
			Key: "password.max_age", Domain: DomainPassword,
			Label:       "Maximum password age",
			Description: "Forced rotation interval (0 = no expiry).",
			Kind:        KindDuration, Default: durV(days(0)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(days(0)), Max: ptr(days(365)), Unit: "days"},
			NIST:       []string{"SP 800-63B §5.1.1.2"}, Harden: HardenNone,
			Rationale: "NIST discourages routine expiry; offered for compliance regimes that mandate it. 0 sentinel makes monotonicity ambiguous, so left freely settable within bounds.",
		},
		{
			Key: "password.min_age", Domain: DomainPassword,
			Label:       "Minimum password age",
			Description: "Shortest time before a password may be changed again (anti-cycling).",
			Kind:        KindDuration, Default: durV(days(0)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(days(0)), Max: ptr(days(30)), Unit: "days"},
			NIST:       []string{"SP 800-53 IA-5(1)"}, Harden: HardenNone,
			Rationale: "Prevents users defeating history depth by rapidly cycling through changes.",
		},

		// ---- Session (SP 800-63B §7) --------------------------------------
		{
			Key: "session.idle_timeout", Domain: DomainSession,
			Label:       "Idle session timeout",
			Description: "Inactivity period after which a session is terminated.",
			Kind:        KindDuration, Default: durV(mins(30)), Tier: TierBasic,
			Constraint: Constraint{Min: ptr(mins(1)), Max: ptr(days(1)), Unit: "minutes"},
			NIST:       []string{"SP 800-63B §7.2"}, Lockable: true, Harden: HardenLower,
			Rationale: "Shorter idle windows reduce exposure of unattended sessions; a scope may shorten but never lengthen.",
		},
		{
			Key: "session.absolute_lifetime", Domain: DomainSession,
			Label:       "Absolute session lifetime",
			Description: "Maximum session duration regardless of activity, forcing re-auth.",
			Kind:        KindDuration, Default: durV(hours(12)), Tier: TierBasic,
			Constraint: Constraint{Min: ptr(mins(5)), Max: ptr(days(7)), Unit: "hours"},
			NIST:       []string{"SP 800-63B §7.2"}, Harden: HardenLower,
			Rationale: "Caps the lifetime of any single authenticated session.",
		},
		{
			Key: "session.access_ttl", Domain: DomainSession,
			Label:       "Access token lifetime",
			Description: "Validity window of a short-lived access token.",
			Kind:        KindDuration, Default: durV(mins(15)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(mins(1)), Max: ptr(hours(1)), Unit: "minutes"},
			NIST:       []string{"SP 800-63B §7.1"}, Harden: HardenLower,
			Rationale: "Short access tokens limit the value of a leaked bearer token; subsumes the legacy token policy.",
		},
		{
			Key: "session.refresh_ttl", Domain: DomainSession,
			Label:       "Refresh token lifetime",
			Description: "Validity window of a refresh token before re-login is required.",
			Kind:        KindDuration, Default: durV(hours(24)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(mins(5)), Max: ptr(days(30)), Unit: "hours"},
			NIST:       []string{"SP 800-63B §7.1"}, Harden: HardenLower,
			Rationale: "Bounds how long offline session continuation is possible.",
		},
		{
			Key: "session.max_concurrent", Domain: DomainSession,
			Label:       "Maximum concurrent sessions",
			Description: "Active sessions allowed per user (0 = unlimited).",
			Kind:        KindInt, Default: intV(0), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(0), Max: ptr(100), Unit: "sessions"},
			NIST:       []string{"SP 800-53 AC-10"}, Harden: HardenNone,
			Rationale: "Limiting concurrency curbs credential sharing and session sprawl. 0 sentinel left freely settable.",
		},

		// ---- Account lifecycle (SP 800-53 AC-2 / AC-7) --------------------
		{
			Key: "account_lifecycle.lockout_threshold", Domain: DomainLifecycle,
			Label:       "Account lockout threshold",
			Description: "Consecutive failed logins before the account is locked (0 = disabled).",
			Kind:        KindInt, Default: intV(5), Tier: TierBasic,
			Constraint: Constraint{Min: ptr(0), Max: ptr(20), Unit: "attempts"},
			NIST:       []string{"SP 800-53 AC-7"}, Harden: HardenNone,
			Rationale: "Throttling failed attempts defeats online password guessing. 0 sentinel left freely settable.",
		},
		{
			Key: "account_lifecycle.lockout_duration", Domain: DomainLifecycle,
			Label:       "Account lockout duration",
			Description: "How long an account stays locked after the threshold is hit.",
			Kind:        KindDuration, Default: durV(mins(15)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(secs(30)), Max: ptr(hours(24)), Unit: "minutes"},
			NIST:       []string{"SP 800-53 AC-7"}, Harden: HardenHigher,
			Rationale: "Longer lockouts slow guessing further; a scope may extend but not shorten.",
		},
		{
			Key: "account_lifecycle.inactivity_disable", Domain: DomainLifecycle,
			Label:       "Disable inactive accounts after",
			Description: "Disable accounts with no activity for this period (0 = never).",
			Kind:        KindDuration, Default: durV(days(90)), Tier: TierAdvanced,
			Constraint: Constraint{Min: ptr(days(0)), Max: ptr(days(365)), Unit: "days"},
			NIST:       []string{"SP 800-53 AC-2(3)"}, Harden: HardenNone,
			Rationale: "Dormant accounts are a standing risk; disabling them shrinks the active attack surface. 0 sentinel left freely settable.",
		},
		{
			Key: "account_lifecycle.require_reset_first_login", Domain: DomainLifecycle,
			Label:       "Force password reset on first login",
			Description: "Require new accounts to set their own password at first sign-in.",
			Kind:        KindBool, Default: boolV(true), Tier: TierBasic,
			NIST: []string{"SP 800-53 IA-5(1)"}, Harden: HardenHigher,
			Rationale: "Ensures admin-set initial credentials are never long-lived.",
		},
		{
			Key: "account_lifecycle.auto_deprovision", Domain: DomainLifecycle,
			Label:       "Auto-deprovision disabled accounts",
			Description: "Permanently remove accounts that have stayed disabled past retention.",
			Kind:        KindBool, Default: boolV(false), Tier: TierAdvanced,
			NIST: []string{"SP 800-53 AC-2"}, Harden: HardenHigher,
			Rationale: "Closes the loop on offboarding so stale identities don't accumulate.",
		},
	})
}
