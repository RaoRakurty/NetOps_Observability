// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/nms"
)

// nms_webhook_secret_test.go — §3 (2026-10-24): an integration saved without a
// webhook secret accepted any body that knew the URL token, because Meraki
// compared "" to "" and generic HMAC'd with an empty key. The handler now
// refuses to verify against an unconfigured secret.

func TestNMSWebhookRefusesAnUnconfiguredSecret(t *testing.T) {
	_, s := newTestServerState(t)
	st := nms.NewMemStore()
	s.nms = newNMSRuntime(st)
	ctx := context.Background()
	if err := st.Upsert(ctx, nms.Integration{Tenant: "t-a", ID: "i-a", Vendor: "generic", Enabled: true, WebhookToken: "tok-a"}); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"event_id":"e1","event_type":"link_down","severity":"high","device_id":"d1"}`)
	post := func(sigKey []byte) int {
		mac := hmac.New(sha256.New, sigKey)
		mac.Write(body)
		req := httptest.NewRequest(http.MethodPost, "/api/nms/webhook/tok-a", bytes.NewReader(body))
		req.Header.Set("X-Correlix-Signature", hex.EncodeToString(mac.Sum(nil)))
		rec := httptest.NewRecorder()
		s.handleNMSWebhook(rec, req)
		return rec.Code
	}

	if code := post(nil); code != http.StatusUnauthorized {
		t.Fatalf("no secret configured: want 401, got %d", code)
	}

	if err := st.SetCredentials(ctx, "t-a", "i-a", map[string]string{"webhook_secret": "s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	if code := post(nil); code != http.StatusUnauthorized {
		t.Fatalf("empty-key signature against a real secret: want 401, got %d", code)
	}
	if code := post([]byte("s3cr3t")); code == http.StatusUnauthorized {
		t.Fatalf("a correctly signed webhook must pass verification, got %d", code)
	}
}
