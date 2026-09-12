// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"strings"
	"testing"
)

// Moved from the integrator with the jira adapter (URL-parse contract).
// TestURLValidationNamesTheActualMistake: the ticketing base-URL parsers and the
// internal CA collapsed "not a URL" and "no host / no scheme" into one message,
// so an operator who forgot `https://` was told their URL was invalid with no
// hint which half failed.
func TestURLValidationNamesTheActualMistake(t *testing.T) {
	if _, err := jiraBaseURL("jira.example.com"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("a scheme-less Jira URL must say so, got %v", err)
	}
	if _, err := jiraBaseURL("https://jira.example.com"); err != nil {
		t.Fatalf("a valid Jira URL must pass: %v", err)
	}
	if _, err := parseInstanceURL("dev123.service-now.com"); err == nil || !strings.Contains(err.Error(), "no host") {
		t.Fatalf("a scheme-less ServiceNow URL must say so, got %v", err)
	}
	if _, err := parseInstanceURL("https://dev123.service-now.com"); err != nil {
		t.Fatalf("a valid ServiceNow URL must pass: %v", err)
	}
}

// TestWSOriginRejectsBothWaysExplicitly: an unparseable Origin and a host-less
// Origin are different facts; both must stay fail-CLOSED (SR-006).
