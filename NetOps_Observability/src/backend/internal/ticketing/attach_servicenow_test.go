// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// attach_servicenow_test.go — the ServiceNow attachment API replayed against an
// httptest server that asserts the DOCUMENTED request shape, not just "a POST
// happened": the path, the three query parameters, the raw (non-multipart)
// body, the real Content-Type, and the Authorization header.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// snowAttachFake records what the instance actually received.
type snowAttachFake struct {
	srv *httptest.Server

	gotPath        string
	gotTable       string
	gotSysID       string
	gotFileName    string
	gotContentType string
	gotBody        []byte
	gotAuth        string
	gotLength      int64

	status    int
	retryHdr  string
	respBody  string
	callCount int
}

func newSnowAttachFake() *snowAttachFake {
	f := &snowAttachFake{status: http.StatusCreated}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.callCount++
		f.gotPath = r.URL.Path
		f.gotTable = r.URL.Query().Get("table_name")
		f.gotSysID = r.URL.Query().Get("table_sys_id")
		f.gotFileName = r.URL.Query().Get("file_name")
		f.gotContentType = r.Header.Get("Content-Type")
		f.gotAuth = r.Header.Get("Authorization")
		f.gotLength = r.ContentLength
		f.gotBody, _ = io.ReadAll(r.Body)
		if f.retryHdr != "" {
			w.Header().Set("Retry-After", f.retryHdr)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.status)
		if f.respBody != "" {
			_, _ = io.WriteString(w, f.respBody)
			return
		}
		_, _ = fmt.Fprintf(w, `{"result":{"sys_id":"att-1","file_name":%q,"size_bytes":"%d","download_link":"%s/api/now/attachment/att-1/file"}}`,
			f.gotFileName, len(f.gotBody), f.srv.URL)
	}))
	return f
}

func (f *snowAttachFake) Close() { f.srv.Close() }

func (f *snowAttachFake) cfg() SystemConfig {
	return SystemConfig{System: "servicenow", InstanceURL: f.srv.URL, AuthType: "basic", User: "svc", Password: "s3cret"}
}

func TestServiceNowAttachFileSendsTheDocumentedRequest(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()

	a := NewServiceNowAdapterWithClient(f.srv.Client())
	payload := []byte("PK\x03\x04 pretend zip")
	res, err := a.attachFile(context.Background(), f.cfg(), "sys-123", "correlix-bundle.zip",
		bytes.NewReader(payload), int64(len(payload)), SnowDefaultMaxAttachBytes, "application/zip")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}

	if f.gotPath != "/api/now/attachment/file" {
		t.Errorf("path = %q, want /api/now/attachment/file", f.gotPath)
	}
	if f.gotTable != "incident" {
		t.Errorf("table_name = %q, want incident", f.gotTable)
	}
	if f.gotSysID != "sys-123" {
		t.Errorf("table_sys_id = %q, want sys-123", f.gotSysID)
	}
	if f.gotFileName != "correlix-bundle.zip" {
		t.Errorf("file_name = %q", f.gotFileName)
	}
	// The API takes RAW bytes, not multipart and not base64.
	if !bytes.Equal(f.gotBody, payload) {
		t.Errorf("body was not the raw bytes: %q", f.gotBody)
	}
	if f.gotContentType != "application/zip" {
		t.Errorf("Content-Type = %q, want the file's real type", f.gotContentType)
	}
	if f.gotLength != int64(len(payload)) {
		t.Errorf("Content-Length = %d, want %d", f.gotLength, len(payload))
	}
	if !strings.HasPrefix(f.gotAuth, "Basic ") {
		t.Errorf("Authorization = %q, want Basic", f.gotAuth)
	}
	if res.ID != "att-1" || res.Transport != "servicenow" || res.Size != int64(len(payload)) {
		t.Errorf("result = %+v", res)
	}
}

func TestServiceNowAttachFileRefusesAboveThePlatformCap(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	a := NewServiceNowAdapterWithClient(f.srv.Client())

	// One byte over com.glide.attachment.max_size's 1024 MB default.
	over := SnowDefaultMaxAttachBytes + 1
	_, err := a.AttachFile(context.Background(), f.cfg(), "sys-123", "huge.zip", bytes.NewReader(nil), over)

	var tooBig AttachTooLargeError
	if !errors.As(err, &tooBig) {
		t.Fatalf("err = %v, want AttachTooLargeError", err)
	}
	if tooBig.Limit != SnowDefaultMaxAttachBytes || tooBig.Size != over {
		t.Errorf("limits = %d/%d, want %d/%d", tooBig.Size, tooBig.Limit, over, SnowDefaultMaxAttachBytes)
	}
	if !strings.Contains(tooBig.Advice, "chunked") {
		t.Errorf("advice should say no chunked upload exists, got %q", tooBig.Advice)
	}
	if f.callCount != 0 {
		t.Errorf("refusal must happen locally: the instance was called %d times", f.callCount)
	}
	// The error must be terminal — retrying identical oversize bytes is waste.
	if retryable(err) {
		t.Error("an oversize bundle must not be retryable")
	}
}

func TestServiceNowAttach413IsAnOversizeOutcomeNotATransportError(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	f.status = http.StatusRequestEntityTooLarge
	f.respBody = `{"error":{"message":"attachment exceeds maximum size"}}`

	a := NewServiceNowAdapterWithClient(f.srv.Client())
	_, err := a.attachFile(context.Background(), f.cfg(), "sys-1", "b.zip",
		bytes.NewReader([]byte("x")), 1, SnowDefaultMaxAttachBytes, "application/zip")

	var tooBig AttachTooLargeError
	if !errors.As(err, &tooBig) {
		t.Fatalf("err = %v, want AttachTooLargeError", err)
	}
	if !strings.Contains(tooBig.Advice, "com.glide.attachment.max_size") {
		t.Errorf("advice should name the instance property, got %q", tooBig.Advice)
	}
}

func TestServiceNowAttach429CarriesRetryAfter(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	f.status = http.StatusTooManyRequests
	f.retryHdr = "17"
	f.respBody = `{"error":{"message":"rate limit"}}`

	a := NewServiceNowAdapterWithClient(f.srv.Client())
	_, err := a.attachFile(context.Background(), f.cfg(), "sys-1", "b.zip",
		bytes.NewReader([]byte("x")), 1, SnowDefaultMaxAttachBytes, "")

	var rl RateLimitedError
	if !errors.As(err, &rl) {
		t.Fatalf("err = %v, want RateLimitedError", err)
	}
	if rl.After.Seconds() != 17 {
		t.Errorf("Retry-After honoured as %v, want 17s", rl.After)
	}
}

func TestServiceNowAttachRejectsAuthFailurePermanently(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	f.status = http.StatusUnauthorized
	f.respBody = `{"error":{"message":"User Not Authenticated"}}`

	a := NewServiceNowAdapterWithClient(f.srv.Client())
	_, err := a.attachFile(context.Background(), f.cfg(), "sys-1", "b.zip",
		bytes.NewReader([]byte("x")), 1, SnowDefaultMaxAttachBytes, "")
	var perm PermanentDeliveryError
	if !errors.As(err, &perm) {
		t.Fatalf("err = %v, want PermanentDeliveryError", err)
	}
	if retryable(err) {
		t.Error("a revoked credential must not be retried")
	}
}

func TestServiceNowAttachValidatesItsInputs(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	a := NewServiceNowAdapterWithClient(f.srv.Client())
	cfg := f.cfg()

	cases := []struct {
		name              string
		sysID, file       string
		r                 io.Reader
		size              int64
		wantErrorContains string
	}{
		{"no sys_id", "", "b.zip", bytes.NewReader(nil), 1, "sys_id"},
		{"no name", "s1", "", bytes.NewReader(nil), 1, "file name"},
		{"no reader", "s1", "b.zip", nil, 1, "reader"},
		{"unknown size", "s1", "b.zip", bytes.NewReader(nil), 0, "size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.AttachFile(context.Background(), cfg, tc.sysID, tc.file, tc.r, tc.size)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrorContains) {
				t.Fatalf("err = %v, want one mentioning %q", err, tc.wantErrorContains)
			}
			if retryable(err) {
				t.Error("a malformed request must not be retried")
			}
		})
	}
}

func TestServiceNowAttachErrorsNeverCarryTheSecret(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	f := newSnowAttachFake()
	defer f.Close()
	f.status = http.StatusForbidden
	f.respBody = `{"error":{"message":"denied"}}`

	a := NewServiceNowAdapterWithClient(f.srv.Client())
	cfg := f.cfg()
	_, err := a.attachFile(context.Background(), cfg, "s1", "b.zip", bytes.NewReader([]byte("x")), 1, 0, "")
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), cfg.Password) {
		t.Fatalf("the password leaked into the error: %v", err)
	}
}
