// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

import (
	"net/http"
	"strings"
	"testing"
)

// The RUM snippet labels an app by its hostname when no data-app is set, so one
// tag injected at a proxy covers many apps; app_source records which it was.

func appSourceEvent(src string) ExperienceEvent {
	return ExperienceEvent{
		ID: "e1", TenantID: "acme", App: "shop.example.com", AppSource: src,
		Type: EventNavigation, ActorType: ActorHuman, Provenance: prov(SourceRUM, 0),
	}
}

func TestAppSourceAcceptsTheClosedSetNormalised(t *testing.T) {
	for in, want := range map[string]string{
		"": "", "attribute": AppSourceAttribute, "hostname": AppSourceHostname, " HostName ": AppSourceHostname,
	} {
		e := appSourceEvent(in)
		if err := e.Validate(); err != nil {
			t.Fatalf("app_source %q refused: %v", in, err)
		}
		if e.AppSource != want {
			t.Fatalf("app_source %q normalised to %q, want %q", in, e.AppSource, want)
		}
	}
}

func TestAppSourceRefusesAnythingElse(t *testing.T) {
	for _, in := range []string{"guess", "host", strings.Repeat("x", 200)} {
		e := appSourceEvent(in)
		err := e.Validate()
		if err == nil || !strings.Contains(err.Error(), "app_source") {
			t.Fatalf("app_source %q accepted: %v", in, err)
		}
	}
}

// The wire decoder refuses unknown fields, so app_source must be a declared wire
// field: a beacon that sends it is accepted and stored with it; an unknown value
// is a visible 400.
func TestIngestCarriesAppSourceAndRefusesAnUnknownOne(t *testing.T) {
	sink := &recordingSink{}
	api, _ := newIngestAPI(t, sink)
	body := `{"events":[{"id":"ev-1","app":"hr.example.com","app_source":"hostname","type":"navigation","action":"route_change","route":"/leave/:id"}]}`
	code, resp := call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil)
	if code != http.StatusAccepted {
		t.Fatalf("a beacon with app_source returned %d %s", code, resp)
	}
	if len(sink.events) != 1 || sink.events[0].AppSource != AppSourceHostname || sink.events[0].App != "hr.example.com" {
		t.Fatalf("app_source was not carried to the lane: %+v", sink.events)
	}
	body = `{"events":[{"id":"ev-2","app":"x","app_source":"guessed","type":"page_view"}]}`
	if code, _ = call(t, api.HandleEvents, http.MethodPost, EventsPath, body, nil); code != http.StatusBadRequest {
		t.Fatalf("an unknown app_source returned %d, want 400", code)
	}
}

func TestAHostnameIsAValidAppLabel(t *testing.T) {
	e := appSourceEvent(AppSourceHostname)
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.App != "shop.example.com" {
		t.Fatalf("the hostname label was rewritten to %q", e.App)
	}
}
