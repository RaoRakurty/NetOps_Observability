package cisco

// cisco_test.go — the parts of the Cisco wire client that the connector tests
// cannot reach: the host pinning applied to a create response's own Field80,
// and the local refusals that must be classifiable as permanent.

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadCXDRefusesAnyHostButThePinnedOne(t *testing.T) {
	// A create response (or a tampered one) naming another host must not
	// redirect the upload — the pinned host wins over anything on the wire.
	c := &Client{HTTP: http.DefaultClient}
	err := c.UploadCXD(context.Background(), "cxd.attacker.example", "695123456", "tok",
		"b.zip", bytes.NewReader([]byte("x")), 1)
	if err == nil {
		t.Fatal("an off-allowlist upload host must be refused")
	}
	if !errors.Is(err, ErrRequestInvalid) {
		t.Errorf("err = %v, want it to wrap ErrRequestInvalid so the caller treats it as permanent", err)
	}
	if !strings.Contains(err.Error(), CXDHost) {
		t.Errorf("the refusal should name the pinned host: %v", err)
	}
	// The published host is accepted (the request then fails on the network,
	// which is fine — the pinning check is what is under test).
	if err := c.UploadCXD(context.Background(), CXDHost, "695123456", "tok", "b.zip",
		bytes.NewReader([]byte("x")), 1); errors.Is(err, ErrRequestInvalid) {
		t.Errorf("the published CXD host must pass the pinning check: %v", err)
	}
}

func TestLocalRefusalsWrapErrRequestInvalid(t *testing.T) {
	c := &Client{HTTP: http.DefaultClient}
	ctx := context.Background()
	for name, err := range map[string]error{
		"no SR or token": c.UploadCXD(ctx, CXDHost, "", "", "b.zip", bytes.NewReader(nil), 1),
		"no file name":   c.UploadCXD(ctx, CXDHost, "sr", "tok", "", bytes.NewReader(nil), 1),
		"no size":        c.UploadCXD(ctx, CXDHost, "sr", "tok", "b.zip", bytes.NewReader(nil), 0),
	} {
		if !errors.Is(err, ErrRequestInvalid) {
			t.Errorf("%s: err = %v, want ErrRequestInvalid", name, err)
		}
	}
	if _, _, err := c.call(ctx, "", PushPath, nil); !errors.Is(err, ErrRequestInvalid) {
		t.Errorf("a missing access token = %v, want ErrRequestInvalid", err)
	}
}

func TestCreateCaseRequiresTheIdempotencyKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the request must not be sent without a transaction id")
	}))
	defer srv.Close()
	c := NewForTest(srv.Client(), srv.URL, srv.URL)
	_, err := c.CreateCase(context.Background(), "tok", CreateRequest{
		Entitlement: Entitlement{CCOID: "c", SerialNumber: "FDO1"},
	})
	if !errors.Is(err, ErrRequestInvalid) {
		t.Fatalf("err = %v, want ErrRequestInvalid", err)
	}
	if !strings.Contains(err.Error(), "customerUniqueTransactionID") {
		t.Errorf("the message should name the field Cisco requires: %v", err)
	}
}

func TestFetchCaseTreatsA404AsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := NewForTest(srv.Client(), srv.URL, srv.URL)
	_, found, err := c.FetchCase(context.Background(), "tok", "695123456")
	if err != nil {
		t.Fatalf("a missing SR is not an error: %v", err)
	}
	if found {
		t.Fatal("found = true for a 404")
	}
}

func TestTokenResponseMustCarryAnAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client()}
	_, _, err := c.Token(context.Background(), srv.URL, "cid", "csec")
	if err == nil || !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("err = %v, want a refusal naming the missing access_token", err)
	}
	// The client secret must never appear in the error.
	if err != nil && strings.Contains(err.Error(), "csec") {
		t.Fatal("the client secret leaked into an error")
	}
}
