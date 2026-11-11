// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"fmt"
	"io"
)

// metrics.go — the route CONFIGURATION's own signals (§10). Delivery counters
// stay in internal/alertwebhook (netops_alert_webhook_*); these answer "is the
// configuration itself healthy, and does it route pages anywhere".
//
// Every series is written on every scrape, zeros included, so "fine" and "not
// measured" are distinguishable to the watchdog and to vmalert.

// WriteMetrics writes the Prometheus text exposition. Nil-safe on both
// arguments (a nil store writes nothing: the feature is not wired).
func WriteMetrics(w io.Writer, s *Store, r *Router) {
	if s == nil {
		return
	}
	ok, everRead := s.Health()
	c := s.Current()
	g := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, v)
	}
	ctr := func(name, help string, v uint64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	g("netops_platform_alert_store_readable",
		"1 when the platform alert settings were read on the last attempt, 0 when the last read failed (the last good settings stay in force).", b2i(ok))
	g("netops_platform_alert_store_ever_read",
		"1 once the platform alert settings have been read since start-up; 0 means NOTHING is in force and platform alerts reach nobody.", b2i(everRead))
	ctr("netops_platform_alert_store_read_failures_total", "Failed reads of the platform alert settings.", s.readFailures.Load())
	ctr("netops_platform_alert_store_save_failures_total", "Failed saves of the platform alert settings (nothing was changed).", s.saveFailures.Load())
	g("netops_platform_alert_page_routed", "1 when page-tier platform alerts reach at least one channel (Platform → Platform alerts), 0 when they reach nobody.", b2i(c.PageRouted()))
	g("netops_platform_alert_warning_routed", "1 when the platform warning summary reaches at least one channel.", b2i(c.WarningRouted()))
	g("netops_platform_alert_sms_budget_remaining", "Text messages left this hour under the platform alert SMS cap (-1 = text messages off).", int64(r.SMSBudgetRemaining()))
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
