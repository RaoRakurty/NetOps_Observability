// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// pagination.go — the ONE bounded-read contract for list endpoints (audit
// F-57 / F-61 / F-74 / F-79, 2026-07-21).
//
// The audit's diagnosis of this class was not "a limit was missing"; it was
// that the endpoints ACCEPTED pagination parameters, answered 200, and did
// something other than what the caller asked:
//
//   - /api/devices parsed nothing and returned the whole table — four different
//     parameter sets produced byte-identical 218 KB responses (F-61).
//   - /api/vulns truncated 7,560 findings to 500 with no offset and no cursor,
//     so 5,560 of them were unreachable at ANY limit (F-79).
//   - /api/incidents accepted ?severity=bogus and applied a DIFFERENT filter
//     (F-74).
//   - /api/audit capped the read at 1,000 while the table grew without bound,
//     so the trail's growth was invisible by construction (F-57).
//
// Three rules follow, and this file is the only place they are implemented:
//
//  1. A parameter is APPLIED or REJECTED — never accepted and ignored.
//     rejectUnknownQuery names the offending key in a 400. Silent acceptance
//     is what made this class invisible for the whole life of the codebase.
//  2. A bounded read reports the caller's TRUE total. Fewer rows than asked
//     for, returned silently, is indistinguishable at the client from "that is
//     all the data there is".
//  3. Range/format errors fail CLOSED (intQuery, F-71 precedent) — never
//     substitute a default the caller did not ask for.
//
// Wire compatibility. `docs/design/sot-provider-model.md` pins /api/devices*
// to an unchanged response shape, and the SPA types /api/audit and
// /api/incidents as bare arrays. So the total is reported on EVERY response as
// headers (always present, shape-neutral), and the JSON envelope carrying the
// same numbers is opt-in via ?envelope=1. Neither is silent.

// The bounded-read pagination CONTRACT moved to internal/httppage (Phase-2
// W4.1). What stays here is per-endpoint POLICY:

// Per-endpoint bounds. The DEFAULT is deliberately the same as the MAX on
// /api/devices: the SPA and every existing API-key client call the endpoint
// with no parameters at all, and quietly handing them 100 of 512 devices would
// be a NEW instance of the very defect this change closes. The ceiling is a
// real bound (an unbounded materialisation of a 50,000-device fleet is a 21 MB
// per-caller response, F-61), and crossing it is announced three ways: the
// X-Page-Complete header, the ?envelope=1 `complete` field, and a structured
// server log — never silence.
const (
	deviceDefaultPage = 5000
	deviceMaxPage     = 5000
)
