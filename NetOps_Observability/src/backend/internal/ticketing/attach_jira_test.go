// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// attach_jira_test.go — the Jira attachment endpoint replayed against an
// httptest server that PARSES the multipart body, so the assertions are on the
// documented wire shape (form field name "file", the X-Atlassian-Token header,
// the API version that matches the deployment) rather than on our own code.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type jiraAttachFake struct {
	srv *httptest.Server

	gotPath      string
	gotXSRF      string
	gotAuth      string
	gotFieldName string
	gotFileName  string
	gotFileBytes []byte
	gotPartCount int
	parseErr     string

	status   int
	respBody string
}

func newJiraAttachFake() *jiraAttachFake {
	f := &jiraAttachFake{status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotPath = r.URL.Path
		f.gotXSRF = r.Header.Get("X-Atlassian-Token")
		f.gotAuth = r.Header.Get("Authorization")

		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			f.parseErr = "content-type: " + err.Error()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				f.parseErr = "part: " + err.Error()
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.gotPartCount++
			f.gotFieldName = part.FormName()
			f.gotFileName = part.FileName()
			f.gotFileBytes, _ = io.ReadAll(part)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		if f.respBody != "" {
			_, _ = io.WriteString(w, f.respBody)
			return
		}
		b, _ := json.Marshal([]map[string]any{{
			"id": "10001", "filename": f.gotFileName, "size": len(f.gotFileBytes),
			"content": f.srv.URL + "/secure/attachment/10001/" + f.gotFileName,
		}})
		_, _ = w.Write(b)
	}))
	return f
}

func (f *jiraAttachFake) Close() { f.srv.Close() }

func (f *jiraAttachFake) cfg() SystemConfig {
	return SystemConfig{System: "jira", InstanceURL: f.srv.URL, AuthType: "basic",
		User: "eng@example.com", APIToken: "atl-token", ProjectKey: "NOC"}
}

func TestJiraAttachCloudUsesV3MultipartAndTheXSRFHeader(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJiraAttachFake()
	defer f.Close()

	a := NewJiraAdapterWithClient(f.srv.Client())
	payload := []byte("PK\x03\x04 bundle bytes")
	res, err := a.AttachFile(context.Background(), f.cfg(), "NOC-42", "correlix-bundle.zip",
		bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if f.parseErr != "" {
		t.Fatalf("server could not parse the multipart body: %s", f.parseErr)
	}
	if f.gotPath != "/rest/api/3/issue/NOC-42/attachments" {
		t.Errorf("path = %q, want the v3 attachments path", f.gotPath)
	}
	if f.gotXSRF != "no-check" {
		t.Errorf("X-Atlassian-Token = %q, want no-check", f.gotXSRF)
	}
	if f.gotFieldName != "file" {
		t.Errorf("form field = %q, want file", f.gotFieldName)
	}
	if f.gotPartCount != 1 {
		t.Errorf("part count = %d, want exactly one file part", f.gotPartCount)
	}
	if !bytes.Equal(f.gotFileBytes, payload) {
		t.Errorf("uploaded bytes differ from the source")
	}
	if !strings.HasPrefix(f.gotAuth, "Basic ") {
		t.Errorf("Cloud must use Basic (email + API token), got %q", f.gotAuth)
	}
	if res.ID != "10001" || res.Transport != "jira" {
		t.Errorf("result = %+v", res)
	}
}

func TestJiraAttachDataCenterUsesV2NocheckAndABearerPAT(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJiraAttachFake()
	defer f.Close()

	a := NewJiraAdapterWithClient(f.srv.Client())
	payload := []byte("small")
	_, err := a.AttachFileWithConfig(context.Background(), f.cfg(),
		JiraAttachConfig{Enabled: true, Deployment: jiraDataCenter},
		"NOC-7", "b.zip", bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if f.gotPath != "/rest/api/2/issue/NOC-7/attachments" {
		t.Errorf("path = %q, want the v2 path on Data Center", f.gotPath)
	}
	if f.gotXSRF != "nocheck" {
		t.Errorf("X-Atlassian-Token = %q, want nocheck (the DC spelling)", f.gotXSRF)
	}
	if f.gotAuth != "Bearer atl-token" {
		t.Errorf("Data Center must use a PAT bearer, got %q", f.gotAuth)
	}
}

func TestJiraAttachAppliesTheDeploymentDefaultCeilings(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJiraAttachFake()
	defer f.Close()
	a := NewJiraAdapterWithClient(f.srv.Client())

	// Data Center's documented default is 10 MB: 11 MB must be refused locally.
	elevenMB := int64(11 << 20)
	_, err := a.AttachFileWithConfig(context.Background(), f.cfg(),
		JiraAttachConfig{Enabled: true, Deployment: jiraDataCenter},
		"NOC-7", "b.zip", bytes.NewReader(nil), elevenMB)
	var tooBig AttachTooLargeError
	if !errors.As(err, &tooBig) {
		t.Fatalf("DC 11 MB: err = %v, want AttachTooLargeError", err)
	}
	if tooBig.Limit != JiraDCDefaultMaxAttachBytes {
		t.Errorf("DC limit = %d, want %d", tooBig.Limit, JiraDCDefaultMaxAttachBytes)
	}

	// The SAME size is fine on Cloud, whose documented default is 1 GB.
	if _, err := a.AttachFileWithConfig(context.Background(), f.cfg(),
		JiraAttachConfig{Enabled: true, Deployment: jiraCloud},
		"NOC-7", "b.zip", bytes.NewReader(make([]byte, 16)), 16); err != nil {
		t.Fatalf("cloud small attach: %v", err)
	}

	// A configured ceiling overrides the documented default in BOTH directions.
	_, err = a.AttachFileWithConfig(context.Background(), f.cfg(),
		JiraAttachConfig{Enabled: true, Deployment: jiraCloud, MaxAttachBytes: 8},
		"NOC-7", "b.zip", bytes.NewReader(nil), 9)
	if !errors.As(err, &tooBig) || tooBig.Limit != 8 {
		t.Fatalf("configured ceiling not honoured: %v", err)
	}
}

func TestJiraAttach413And429Classify(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	for _, tc := range []struct {
		name   string
		status int
		check  func(t *testing.T, err error)
	}{
		{"413 is oversize", http.StatusRequestEntityTooLarge, func(t *testing.T, err error) {
			var e AttachTooLargeError
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want AttachTooLargeError", err)
			}
		}},
		{"429 is rate limited", http.StatusTooManyRequests, func(t *testing.T, err error) {
			var e RateLimitedError
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want RateLimitedError", err)
			}
		}},
		{"401 is permanent", http.StatusUnauthorized, func(t *testing.T, err error) {
			var e PermanentDeliveryError
			if !errors.As(err, &e) {
				t.Fatalf("err = %v, want PermanentDeliveryError", err)
			}
			if retryable(err) {
				t.Error("a revoked credential must not be retried")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newJiraAttachFake()
			defer f.Close()
			f.status = tc.status
			f.respBody = `{"errorMessages":["nope"]}`
			a := NewJiraAdapterWithClient(f.srv.Client())
			_, err := a.AttachFile(context.Background(), f.cfg(), "NOC-1", "b.zip",
				bytes.NewReader([]byte("x")), 1)
			tc.check(t, err)
		})
	}
}

func TestJiraAttachSanitizesTheFileName(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newJiraAttachFake()
	defer f.Close()
	a := NewJiraAdapterWithClient(f.srv.Client())

	// A traversal-shaped, quote-bearing, CRLF-bearing name must not reach the
	// MIME header intact.
	_, err := a.AttachFile(context.Background(), f.cfg(), "NOC-1",
		"../../etc/\"pass\r\nwd.zip", bytes.NewReader([]byte("x")), 1)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if strings.ContainsAny(f.gotFileName, `/\"`) || strings.Contains(f.gotFileName, "\n") {
		t.Fatalf("unsafe file name reached the server: %q", f.gotFileName)
	}
	if f.gotFileName != "passwd.zip" {
		t.Errorf("file name = %q, want passwd.zip", f.gotFileName)
	}
}
