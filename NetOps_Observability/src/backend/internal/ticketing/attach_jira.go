package ticketing

// attach_jira.go — Jira issue attachments, the second half of Tier 1.
//
// Wire contract (research §1, Jira row, citing
// https://support.atlassian.com/jira/kb/how-to-add-an-attachment-to-a-jira-issue-using-rest-api/):
//
//	POST /rest/api/3/issue/{issueIdOrKey}/attachments   (Cloud)
//	Content-Type: multipart/form-data
//	form field name: "file"
//	X-Atlassian-Token: no-check          (Data Center's docs spell it "nocheck")
//
// Deployment matters for three things at once and they move together, so one
// setting selects all three (research §1, Jira row):
//
//	                 API path        auth              default ceiling
//	Cloud            /rest/api/3     email + API token 1 GB   (max 2 GB)
//	Data Center      /rest/api/2     PAT bearer        10 MB  (max 2 GB)
//
// The ceiling is READ FROM CONFIG with those defaults, because both are
// instance properties an admin can raise or lower.
//
// The body is STREAMED through an io.Pipe: a 1 GB bundle is never held in
// memory (§9 bounded resources).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"time"

	"netops/backend/safehttp"
)

const (
	jiraCloud      = "cloud"
	jiraDataCenter = "datacenter"
	// JiraCloudDefaultMaxAttachBytes / JiraDCDefaultMaxAttachBytes are the
	// vendors' documented DEFAULTS for the attachment-size property.
	JiraCloudDefaultMaxAttachBytes int64 = 1 << 30  // 1 GB (Cloud default)
	JiraDCDefaultMaxAttachBytes    int64 = 10 << 20 // 10 MB (Data Center default)
	jiraAttachTimeout                    = 10 * time.Minute
)

// jiraDeployment normalizes the configured deployment; blank means Cloud, which
// is the majority deployment and the one the v3 path serves.
func jiraDeployment(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", jiraCloud, "jira-cloud":
		return jiraCloud
	case jiraDataCenter, "dc", "server", "jira-dc":
		return jiraDataCenter
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// jiraAttachDefaults resolves (api path prefix, XSRF header value, ceiling) for
// a deployment. Everything here is a citation, not a preference.
func jiraAttachDefaults(deployment string) (apiPrefix, xsrfToken string, limit int64) {
	if jiraDeployment(deployment) == jiraDataCenter {
		return "/rest/api/2", "nocheck", JiraDCDefaultMaxAttachBytes
	}
	return "/rest/api/3", "no-check", JiraCloudDefaultMaxAttachBytes
}

// AttachFile uploads one file to a Jira issue using the CLOUD defaults
// (/rest/api/3, X-Atlassian-Token: no-check, 1 GB ceiling). A Data Center
// instance, or an instance whose attachment property was changed, must go
// through AttachFileWithConfig so the documented default is not applied blindly.
//
// Single attempt by design — an io.Reader cannot be replayed. AttachBundle
// wraps this with the bounded retry, re-opening the bundle each attempt.
func (a *JiraAdapter) AttachFile(ctx context.Context, cfg SystemConfig, ticketID, name string, r io.Reader, size int64) (AttachResult, error) {
	return a.AttachFileWithConfig(ctx, cfg, JiraAttachConfig{Deployment: jiraCloud}, ticketID, name, r, size)
}

// AttachFileWithConfig is AttachFile with the tenant's deployment and ceiling.
func (a *JiraAdapter) AttachFileWithConfig(ctx context.Context, cfg SystemConfig, ac JiraAttachConfig, issueKey, name string, r io.Reader, size int64) (AttachResult, error) {
	if strings.TrimSpace(issueKey) == "" {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("jira: attach requires the issue id or key")}
	}
	name = sanitizeFileName(name)
	if r == nil {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("jira: attach requires a reader")}
	}
	if size <= 0 {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("jira: attach requires the file size up front")}
	}
	prefix, xsrf, limit := jiraAttachDefaults(ac.Deployment)
	if ac.MaxAttachBytes > 0 {
		limit = ac.MaxAttachBytes
	}
	if size > limit {
		return AttachResult{}, AttachTooLargeError{
			Transport: "jira", Size: size, Limit: limit,
			Advice: "raise the instance's attachment size property, use the smaller bundle profile, or attach a link-only case description",
		}
	}

	base, err := jiraBaseURL(cfg.InstanceURL)
	if err != nil {
		return AttachResult{}, PermanentDeliveryError{err}
	}
	if err := safehttp.ValidateURL(base.Hostname()); err != nil {
		return AttachResult{}, PermanentDeliveryError{err}
	}
	path := prefix + "/issue/" + url.PathEscape(issueKey) + "/attachments"
	reqURL, err := url.Parse(strings.TrimRight(base.String(), "/") + path)
	if err != nil {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("jira: bad attachment url")}
	}
	if !strings.EqualFold(reqURL.Hostname(), base.Hostname()) {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("jira: request host %q escaped configured base URL", reqURL.Hostname())}
	}

	ctx, cancel := context.WithTimeout(ctx, jiraAttachTimeout)
	defer cancel()

	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		// CloseWithError(nil) is Close; any writer-side failure is handed to the
		// reader so the request fails loudly instead of truncating the upload.
		_ = pw.CloseWithError(writeJiraFilePart(mw, name, io.LimitReader(r, size)))
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), pr)
	if err != nil {
		_ = pr.CloseWithError(err) // release the writer goroutine
		return AttachResult{}, fmt.Errorf("jira: build attach request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", mw.FormDataContentType())
	// Jira refuses a multipart upload without this header (XSRF check opt-out).
	req.Header.Set("X-Atlassian-Token", xsrf)
	applyJiraAuth(req, cfg, ac.Deployment)

	resp, err := a.client().Do(req)
	if err != nil {
		_ = pr.CloseWithError(err) // unblock the writer goroutine on transport failure
		return AttachResult{}, fmt.Errorf("jira: POST %s: request failed", redactPath(path))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, jiraMaxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AttachResult{}, classifyJiraAttachStatus(resp, raw, path, size, limit)
	}

	// The attachment endpoint answers with an ARRAY of created attachments.
	var out []struct {
		ID       string `json:"id"`
		Self     string `json:"self"`
		Filename string `json:"filename"`
		Size     int64  `json:"size"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return AttachResult{}, fmt.Errorf("jira: attachment response was not the documented array of attachments: %w", err)
	}
	if len(out) == 0 {
		// Parsed fine but empty: Jira accepted the request and created nothing —
		// a distinct condition from a malformed reply, and the caller must not
		// mistake it for a successful attach.
		return AttachResult{}, fmt.Errorf("jira: attachment response carried no attachment for %q", name)
	}
	return AttachResult{
		ID:        out[0].ID,
		URL:       out[0].Content,
		Name:      orDefault(out[0].Filename, name),
		Size:      size,
		At:        time.Now().UTC(),
		Transport: "jira",
	}, nil
}

// writeJiraFilePart writes the single "file" part and closes the multipart
// writer. The filename is quoted and pre-sanitized, so it cannot inject a header.
func writeJiraFilePart(mw *multipart.Writer, name string, r io.Reader) error {
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, name))
	h.Set("Content-Type", "application/octet-stream")
	part, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, r); err != nil {
		return err
	}
	return mw.Close()
}

// applyJiraAuth: Cloud is Basic with the account email + API token (Atlassian
// disabled password Basic on 2019-06-03); Data Center is a PAT bearer.
func applyJiraAuth(req *http.Request, cfg SystemConfig, deployment string) {
	if jiraDeployment(deployment) == jiraDataCenter {
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
		return
	}
	req.SetBasicAuth(cfg.User, cfg.APIToken)
}

// classifyJiraAttachStatus maps a non-2xx onto retry semantics. 413 means the
// instance property is below the configured ceiling — an oversize outcome, not
// a transport failure. 429 honours Retry-After: Jira Cloud enforces 20 writes
// per 2 s PER ISSUE, which is exactly the create→attach→retry pattern
// (research §8.5).
func classifyJiraAttachStatus(resp *http.Response, raw []byte, path string, size, limit int64) error {
	err := fmt.Errorf("jira: POST %s returned %d: %s", redactPath(path), resp.StatusCode, jiraError(raw))
	switch resp.StatusCode {
	case http.StatusRequestEntityTooLarge:
		return AttachTooLargeError{
			Transport: "jira", Size: size, Limit: limit,
			Advice: "the instance's attachment size property is lower than the configured limit; lower max_attach_bytes or use the smaller bundle profile",
		}
	case http.StatusTooManyRequests:
		return RateLimitedError{After: retryAfterOr(resp, 30*time.Second)}
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return PermanentDeliveryError{err}
	default:
		return err
	}
}
