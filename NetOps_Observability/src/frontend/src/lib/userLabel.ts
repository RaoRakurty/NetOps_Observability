// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// userLabel.ts — the ONE rule for naming a person on screen (tracker 300 §4.7).
//
// A federated account has no login handle: its `username` IS its opaque
// principal id (`fed_<tenant>_<hash>`), minted from the identity tuple. Showing
// that string would put a meaningless hash where an operator expects a name, so
// the design forbids it outright. The username is displayable only for a LOCAL
// account, where it is the name someone actually types to sign in.
//
//   display_name  →  the IdP's or the operator's own label, always preferred
//   username      →  LOCAL accounts only
//   email         →  the federated fallback
//   "Signed in"   →  a federated account with neither; never a `fed_` string
//
// Anything with a `username`, an optional `display_name`, `email` and
// `auth_source` fits — AuthUser and AdminUser both do.

export type LabelledUser = {
  username?: string;
  display_name?: string;
  email?: string;
  auth_source?: string;
};

/** isLocalAccount mirrors the backend predicate: an empty source is legacy LOCAL. */
export function isLocalAccount(u: LabelledUser | null | undefined): boolean {
  const s = (u?.auth_source ?? "").trim().toLowerCase();
  return s === "" || s === "local";
}

/** userLabel is what the UI shows for a person. It never returns a `fed_` id. */
export function userLabel(u: LabelledUser | null | undefined, fallback = "Signed in"): string {
  const display = (u?.display_name ?? "").trim();
  if (display) return display;
  if (isLocalAccount(u)) {
    const name = (u?.username ?? "").trim();
    if (name) return name;
  }
  const email = (u?.email ?? "").trim();
  if (email) return email;
  return fallback;
}
