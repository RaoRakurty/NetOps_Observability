// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// attach_servicenow.go — the one thing the ServiceNow adapter was missing:
// AttachFile.
//
// Wire contract (research §1, ServiceNow row, citing
// https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AttachmentAPI.html):
//
//	POST /api/now/attachment/file?table_name=incident&table_sys_id=<sys_id>&file_name=<name>
//	Content-Type: the file's REAL type (application/zip for a bundle)
//	body: the RAW bytes — not multipart, not base64
//
// Ceiling: the instance property com.glide.attachment.max_size, DEFAULT 1024 MB
// (https://www.servicenow.com/docs/csh?topicname=sc-max-allowed-attachment-size.html).
// There is NO documented chunked or resumable upload, so a bundle above the
// ceiling is refused with an honest AttachTooLargeError that names the smaller
// profile — it is never silently split (research §8.2).
//
// Note the OTHER ServiceNow ceiling, which this path deliberately does not hit:
// the inbound EMAIL action caps at glide.email.inbound.max_total_attachment_size_bytes
// = 18874368 (18 MiB) total. That is the email connector's problem, not the
// REST attachment API's.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"netops/backend/safehttp"
)

const (
	// SnowAttachTable is the table an escalation bundle attaches to. The RCA
	// ticketing lane files incidents; the attachment must land on the same record.
	SnowAttachTable = "incident"
	// SnowDefaultMaxAttachBytes is com.glide.attachment.max_size's documented
	// default of 1024 MB. An instance that changed the property configures it.
	SnowDefaultMaxAttachBytes int64 = 1024 << 20
	// snowAttachTimeout bounds one upload conversation. Larger than the 20 s
	// Table API budget because a 1 GB body legitimately takes longer, still
	// bounded (§9: all IO has a timeout).
	snowAttachTimeout = 10 * time.Minute
)

// AttachFile uploads one file to a ServiceNow record and returns what the
// instance stored. size is REQUIRED: the ceiling must be enforced before a byte
// leaves this process, and ServiceNow wants a Content-Length.
//
// Single attempt by design — an io.Reader cannot be replayed. AttachBundle
// wraps this with the bounded retry, re-opening the bundle each attempt.
func (a *ServiceNowAdapter) AttachFile(ctx context.Context, cfg SystemConfig, ticketID, name string, r io.Reader, size int64) (AttachResult, error) {
	return a.attachFile(ctx, cfg, ticketID, name, r, size, SnowDefaultMaxAttachBytes, "")
}

// attachFile is the implementation; limit and contentType are resolved by the
// caller (the connector reads the tenant's configured ceiling).
func (a *ServiceNowAdapter) attachFile(ctx context.Context, cfg SystemConfig, sysID, name string, r io.Reader, size int64, limit int64, contentType string) (AttachResult, error) {
	if strings.TrimSpace(sysID) == "" {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: attach requires the record sys_id")}
	}
	if strings.TrimSpace(name) == "" {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: attach requires a file name")}
	}
	if r == nil {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: attach requires a reader")}
	}
	if size <= 0 {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: attach requires the file size up front")}
	}
	if limit <= 0 {
		limit = SnowDefaultMaxAttachBytes
	}
	if size > limit {
		return AttachResult{}, AttachTooLargeError{
			Transport: "servicenow", Size: size, Limit: limit,
			Advice: "ServiceNow publishes no chunked or resumable upload; use the smaller bundle profile or the link-only case description",
		}
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	base, err := parseInstanceURL(cfg.InstanceURL)
	if err != nil {
		return AttachResult{}, PermanentDeliveryError{err}
	}
	if err := safehttp.ValidateURL(base.Hostname()); err != nil {
		return AttachResult{}, PermanentDeliveryError{err}
	}
	q := url.Values{}
	q.Set("table_name", SnowAttachTable)
	q.Set("table_sys_id", sysID)
	q.Set("file_name", name)
	reqURL, err := url.Parse(strings.TrimRight(base.String(), "/") + "/api/now/attachment/file?" + q.Encode())
	if err != nil {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: bad attachment url")}
	}
	// Defence in depth: the composed URL must stay on the configured instance.
	if !strings.EqualFold(reqURL.Hostname(), base.Hostname()) {
		return AttachResult{}, PermanentDeliveryError{fmt.Errorf("servicenow: request host %q escaped configured instance", reqURL.Hostname())}
	}

	ctx, cancel := context.WithTimeout(ctx, snowAttachTimeout)
	defer cancel()
	// LimitReader is the belt to the size check's braces: a reader that lies
	// about its length cannot stream past the ceiling we validated.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL.String(), io.LimitReader(r, size))
	if err != nil {
		return AttachResult{}, fmt.Errorf("servicenow: build attach request: %w", err)
	}
	req.ContentLength = size
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", contentType)
	applySnowAuth(req, cfg)

	resp, err := a.client().Do(req)
	if err != nil {
		// Never echo err: a transport error can embed the URL, and the URL is the
		// only place a credential could travel here. Say what failed, not how.
		return AttachResult{}, fmt.Errorf("servicenow: POST /api/now/attachment/file: request failed")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, snowMaxRespBytes)) // best-effort diagnostic snippet
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return AttachResult{}, classifySnowAttachStatus(resp, raw, size, limit)
	}

	var out struct {
		Result struct {
			SysID       string `json:"sys_id"`
			FileName    string `json:"file_name"`
			SizeBytes   string `json:"size_bytes"`
			DownloadURL string `json:"download_link"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return AttachResult{}, fmt.Errorf("servicenow: decode attachment response: %w", err)
	}
	if out.Result.SysID == "" {
		return AttachResult{}, fmt.Errorf("servicenow: attachment response carried no sys_id")
	}
	return AttachResult{
		ID:        out.Result.SysID,
		URL:       out.Result.DownloadURL,
		Name:      orDefault(out.Result.FileName, name),
		Size:      size,
		At:        time.Now().UTC(),
		Transport: "servicenow",
	}, nil
}

// classifySnowAttachStatus maps a non-2xx onto the worker's retry semantics.
// 413 is the instance saying the property is lower than we believed — that is
// an oversize outcome, not a transport error to retry.
func classifySnowAttachStatus(resp *http.Response, raw []byte, size, limit int64) error {
	err := fmt.Errorf("servicenow: POST /api/now/attachment/file returned %d: %s", resp.StatusCode, snowError(raw))
	switch resp.StatusCode {
	case http.StatusRequestEntityTooLarge:
		return AttachTooLargeError{
			Transport: "servicenow", Size: size, Limit: limit,
			Advice: "the instance's com.glide.attachment.max_size is lower than the configured limit; lower max_attach_bytes or use the smaller bundle profile",
		}
	case http.StatusTooManyRequests:
		// ServiceNow publishes no default rate limit, so the header is the only
		// truth available (research §8.5).
		return RateLimitedError{After: retryAfterOr(resp, 30*time.Second)}
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return PermanentDeliveryError{err}
	default:
		return err
	}
}

// applySnowAuth sets the Authorization header from the tenant's connection.
// The secret travels ONLY here — never in a URL, a log field or an error.
func applySnowAuth(req *http.Request, cfg SystemConfig) {
	if strings.EqualFold(strings.TrimSpace(cfg.AuthType), "token") {
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
		return
	}
	req.SetBasicAuth(cfg.User, cfg.Password)
}
