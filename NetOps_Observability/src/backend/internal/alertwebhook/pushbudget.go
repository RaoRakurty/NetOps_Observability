// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package alertwebhook

// pushbudget.go — this route's view of the OUTBOUND PUSH BUDGET.
//
// WHY THIS FILE IS NOW FIVE LINES. The bucket used to live here and was keyed
// PER TOPIC — one bucket per receiver, which is one bucket per route. That key
// was wrong, and a second live incident proved it: **ntfy.sh rate-limits per
// source IP**, so this route and the PRODUCT notification channel (notify/
// ntfy.go) spend ONE server-side allowance while each thought it owned a
// private one. Fourteen product pushes an hour, each retried four times against
// `429`, could therefore starve a PAGE on this route without ever touching the
// gauge this route watches.
//
// The bucket moved to notify/pushbudget.go and is keyed by the push SERVER
// HOST, shared by both senders, with the page reserve honoured across them.
// This route's semantics are unchanged: it takes its token at ENQUEUE (see
// pushHost), synchronously with the request, so a refusal is decided and
// counted at a point the operator can correlate with the alert that caused it —
// and it therefore attaches NO budget to its own notify.Ntfy sender, which
// would otherwise take a second token for the same push.
//
// The operator knobs keep their names (EnvPushBudget /
// EnvPushBudgetPageReserve, see hostroute.go) and now govern that shared,
// per-server allowance. Documented in docs/runbooks/engine-not-consuming.md.

import "netops/backend/notify"

// Budget defaults, re-exported from notify so this package's env parsing and
// the bucket that consumes it can never disagree about the default.
const (
	// DefaultPushBudget is the sustained outbound push allowance per hour for
	// a push server host, across every sender in this process.
	DefaultPushBudget = notify.DefaultPushBudget
	// DefaultPageReserve is how many of those tokens ONLY a page (or the
	// resolution of one) may spend.
	DefaultPageReserve = notify.DefaultPageReserve
)
