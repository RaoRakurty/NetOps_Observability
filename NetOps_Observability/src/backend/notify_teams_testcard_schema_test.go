// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// notify_teams_testcard_schema_test.go — tracker 455: the card the platform
// admin's "Send test" button posts (/api/notify/teams/test → testAlert) is valid
// against Microsoft's official Adaptive Card 1.4 schema.

import (
	"strings"
	"testing"

	"netops/backend/internal/adaptivecard"
	"netops/backend/notify"
)

func TestTheTeamsTestCardIsValidAgainstTheOfficialSchema(t *testing.T) {
	v, err := adaptivecard.New14(adaptivecard.TeamsHostExtensions...)
	if err != nil {
		t.Fatal(err)
	}
	env := notify.TeamsAlertMessage(testAlert()).Envelope()
	atts, ok := env["attachments"].([]map[string]any)
	if !ok || len(atts) != 1 {
		t.Fatalf("not the Teams message envelope: %v", env)
	}
	if errs := v.ValidateCard(atts[0]["content"]); errs != nil {
		t.Fatalf("the Teams test card is refused by the Adaptive Card 1.4 schema:\n  %s", strings.Join(errs, "\n  "))
	}
}
