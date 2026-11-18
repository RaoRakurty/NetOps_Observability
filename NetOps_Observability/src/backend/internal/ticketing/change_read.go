// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// change_read.go — READ one change record from a workspace's ITSM system, so Iris
// can review a change plan the operator names by its ticket ("is CHG0012345
// ready?"). Read-only: one GET, nothing written, nothing created. It is a separate
// optional interface (ChangeReader) rather than a new Adapter method, so adapters
// that have no change records (PagerDuty, the chat lanes) are untouched.
//
// The text it returns is CUSTOMER-WRITTEN and untrusted: the caller fences it as
// data and never sends it to a model as instructions. Each field is bounded.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// MaxChangeFieldBytes bounds each text field of a change read back.
const MaxChangeFieldBytes = 4 << 10

// RemoteChange is the subset of a change record a plan review reads.
type RemoteChange struct {
	Number             string
	SysID              string
	Title              string
	Description        string
	ImplementationPlan string
	BackoutPlan        string
	TestPlan           string
	Risk               string
	State              string
	// Start and End are the planned window as the system states it (display
	// text; zero-length when unset), and StartAt/EndAt the parsed times when the
	// text is a timestamp.
	Start   string
	End     string
	StartAt time.Time
	EndAt   time.Time
}

// ChangeReader is implemented by an adapter that can read a change record by its
// number. found=false when no such record exists (or the account cannot see it).
type ChangeReader interface {
	FetchChange(ctx context.Context, cfg SystemConfig, number string) (RemoteChange, bool, error)
}

var (
	reSnowChange = regexp.MustCompile(`^CHG\d{4,12}$`)
	reJiraKey    = regexp.MustCompile(`^[A-Z][A-Z0-9]{1,9}-\d{1,9}$`)
)

// ValidChangeNumber reports whether number is a change reference this package
// will put in a request for system ("servicenow" or "jira").
func ValidChangeNumber(system, number string) bool {
	switch system {
	case "servicenow":
		return reSnowChange.MatchString(number)
	case "jira":
		return reJiraKey.MatchString(number)
	}
	return false
}

// clipField bounds one field, on a rune boundary.
func clipField(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= MaxChangeFieldBytes {
		return s
	}
	cut := MaxChangeFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// FetchChange reads one change_request by its number from the Table API.
func (a *ServiceNowAdapter) FetchChange(ctx context.Context, cfg SystemConfig, number string) (RemoteChange, bool, error) {
	if !ValidChangeNumber("servicenow", number) {
		return RemoteChange{}, false, fmt.Errorf("servicenow: %q is not a change number", number)
	}
	fields := "number,sys_id,short_description,description,implementation_plan,backout_plan,test_plan,risk,state,start_date,end_date"
	path := "/api/now/table/change_request?sysparm_limit=1&sysparm_display_value=true&sysparm_exclude_reference_link=true" +
		"&sysparm_query=" + url.QueryEscape("number="+number) + "&sysparm_fields=" + url.QueryEscape(fields)
	raw, status, err := a.do(ctx, cfg, http.MethodGet, path, nil)
	if err != nil {
		if status == http.StatusNotFound {
			return RemoteChange{}, false, nil
		}
		return RemoteChange{}, false, err
	}
	var resp struct {
		Result []map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return RemoteChange{}, false, fmt.Errorf("servicenow: decode change: %w", err)
	}
	if len(resp.Result) == 0 {
		return RemoteChange{}, false, nil
	}
	r := resp.Result[0]
	ch := RemoteChange{
		Number:             clipField(orDefault(asString(r["number"]), number)),
		SysID:              clipField(asString(r["sys_id"])),
		Title:              clipField(asString(r["short_description"])),
		Description:        clipField(asString(r["description"])),
		ImplementationPlan: clipField(asString(r["implementation_plan"])),
		BackoutPlan:        clipField(asString(r["backout_plan"])),
		TestPlan:           clipField(asString(r["test_plan"])),
		Risk:               clipField(asString(r["risk"])),
		State:              clipField(asString(r["state"])),
		Start:              clipField(asString(r["start_date"])),
		End:                clipField(asString(r["end_date"])),
	}
	ch.StartAt, ch.EndAt = parseSnowTime(ch.Start), parseSnowTime(ch.End)
	return ch, true, nil
}

// FetchChange reads one Jira issue (a change tracked as an issue) by its key.
// Jira has no standard rollback or test-plan fields; the summary and description
// carry the plan, and the review reads them as written.
func (a *JiraAdapter) FetchChange(ctx context.Context, cfg SystemConfig, key string) (RemoteChange, bool, error) {
	if !ValidChangeNumber("jira", key) {
		return RemoteChange{}, false, fmt.Errorf("jira: %q is not an issue key", key)
	}
	raw, status, err := a.do(ctx, cfg, http.MethodGet, "/rest/api/2/issue/"+url.PathEscape(key)+"?fields=summary,description,status", nil)
	if err != nil {
		if status == http.StatusNotFound {
			return RemoteChange{}, false, nil
		}
		return RemoteChange{}, false, err
	}
	var resp struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Summary     string          `json:"summary"`
			Description json.RawMessage `json:"description"`
			Status      struct {
				Name string `json:"name"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return RemoteChange{}, false, fmt.Errorf("jira: decode issue: %w", err)
	}
	var desc string
	if len(resp.Fields.Description) > 0 && string(resp.Fields.Description) != "null" {
		if err := json.Unmarshal(resp.Fields.Description, &desc); err != nil {
			// A rich-text (ADF) description: not plain text, so it is not read as one.
			desc = ""
		}
	}
	return RemoteChange{
		Number: clipField(orDefault(resp.Key, key)), SysID: clipField(resp.ID),
		Title: clipField(resp.Fields.Summary), Description: clipField(desc), State: clipField(resp.Fields.Status.Name),
	}, true, nil
}
