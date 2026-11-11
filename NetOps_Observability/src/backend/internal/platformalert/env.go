// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"sort"
	"strings"
)

// env.go — the RETIRED environment contract.
//
// Until 2026-11-11 the platform route's destination was read from
// PLATFORM_ALERTS_NTFY_TOPIC / _SERVER / _TOKEN, falling back to
// WATCHDOG_NTFY_TOPIC. The owner blocked that ("configured from the GUI and
// not via env. Block that option."), so NOTHING here reads those values. The
// names are kept only so the wiring layer can say — once, at boot, as a WARN
// and on the admin page — that a value someone left in the environment does
// nothing and where the setting lives now.
//
// THERE IS DELIBERATELY NO IMPORT of a leftover value into the store. A silent
// import would be the env path by another name; the administrator enters the
// destination on the page (which takes a minute and is audited).
//
// WATCHDOG_NTFY_TOPIC is NOT retired: it stays in the api environment because
// the PRODUCT ntfy channel refuses to point at the watchdog's topic
// (notify_config.go). It is only no longer the platform route's fallback, so
// it is reported as ignored-for-this-route only when the route has no ntfy
// destination of its own (WatchdogFallbackIgnored).

// RetiredEnv returns the variable names this route no longer reads.
func RetiredEnv() []string {
	return []string{"PLATFORM_ALERTS_NTFY_TOPIC", "PLATFORM_ALERTS_NTFY_SERVER", "PLATFORM_ALERTS_NTFY_TOKEN"}
}

// WatchdogTopicEnv is the external watchdog's topic variable (see above).
const WatchdogTopicEnv = "WATCHDOG_NTFY_TOPIC"

// RetiredEnvSet returns the retired names that are set to a non-blank value,
// sorted. lookup is os.LookupEnv in production (injected: the package stays
// env-free and the function is testable).
func RetiredEnvSet(lookup func(string) (string, bool)) []string {
	var out []string
	for _, k := range RetiredEnv() {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// WatchdogFallbackIgnored reports whether WATCHDOG_NTFY_TOPIC is set while the
// route has no ntfy destination — the one case where an operator could still
// believe the old fallback is carrying platform alerts.
func WatchdogFallbackIgnored(lookup func(string) (string, bool), c Config) bool {
	v, ok := lookup(WatchdogTopicEnv)
	return ok && strings.TrimSpace(v) != "" && !c.ntfyLive()
}
