package integration

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// jira.go — Jira inbound translator. Jira Cloud/automation webhooks are signed
// with an HMAC-SHA256 over the body in the X-Hub-Signature header
// ("sha256=<hex>"), keyed by the per-tenant webhook secret.

type jiraProvider struct{}

// NewJiraProvider returns the Jira inbound translator.
func NewJiraProvider() Provider { return jiraProvider{} }

func (jiraProvider) Type() string { return "jira" }
func (jiraProvider) Capabilities() Capabilities {
	return Capabilities{Ticketing: true, Webhooks: true, Polling: true, Interactive: false}
}

func (jiraProvider) VerifyWebhook(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrSignatureInvalid
	}
	expected := "sha256=" + hmacSHA256Hex([]byte(secret), body)
	if !constEq(r.Header.Get("X-Hub-Signature"), expected) {
		return ErrSignatureInvalid
	}
	return nil
}

type jiraWebhook struct {
	WebhookEvent string `json:"webhookEvent"` // jira:issue_updated | comment_created | …
	Timestamp    int64  `json:"timestamp"`    // epoch millis
	Issue        struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Status   struct{ Name string } `json:"status"`
			Assignee *struct {
				DisplayName string `json:"displayName"`
			} `json:"assignee"`
			Summary string `json:"summary"`
		} `json:"fields"`
	} `json:"issue"`
	Changelog *struct {
		ID string `json:"id"`
	} `json:"changelog"`
	Comment *struct {
		ID     string `json:"id"`
		Body   string `json:"body"`
		Author struct {
			DisplayName string `json:"displayName"`
		} `json:"author"`
	} `json:"comment"`
}

func (jiraProvider) Normalize(tenant string, body []byte) ([]IntegrationEvent, error) {
	var p jiraWebhook
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}

	seq := int64(0)
	if p.Changelog != nil {
		if n, err := strconv.ParseInt(p.Changelog.ID, 10, 64); err == nil {
			seq = n
		}
	}
	if seq == 0 {
		seq = p.Timestamp // fall back to epoch-millis ordering
	}
	occurred := time.Time{}
	if p.Timestamp > 0 {
		occurred = time.UnixMilli(p.Timestamp).UTC()
	}

	ev := IntegrationEvent{
		Provider: "jira",
		Tenant:   tenant,
		// Correlates to the incident's external_ticket_id, stored as the Jira KEY
		// (NOC-1) on outbound. Prefer key; fall back to numeric id.
		ExternalID: firstNonEmpty(p.Issue.Key, p.Issue.ID),
		ExternalSeq:   seq,
		OccurredAt:    occurred,
		ExternalState: p.Issue.Fields.Status.Name,
		Raw:           body,
	}
	if p.Issue.Fields.Assignee != nil {
		ev.Assignee = p.Issue.Fields.Assignee.DisplayName
	}

	// A comment event carries its own id + body and is classified distinctly.
	if p.Comment != nil {
		ev.Type = EventCommentAdded
		ev.Comment = p.Comment.Body
		ev.Actor = p.Comment.Author.DisplayName
		ev.ProviderEvtID = firstNonEmpty("comment:"+p.Comment.ID, p.WebhookEvent)
		return []IntegrationEvent{ev}, nil
	}

	ev.Type = stateToEventType(p.Issue.Fields.Status.Name)
	ev.ProviderEvtID = firstNonEmpty(jiraSeqID(p.Issue.ID, seq), p.WebhookEvent)
	return []IntegrationEvent{ev}, nil
}

func jiraSeqID(issueID string, seq int64) string {
	if issueID == "" || seq == 0 {
		return ""
	}
	return issueID + ":" + strconv.FormatInt(seq, 10)
}
