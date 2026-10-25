// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Rows trimmed from a live 20.6.1 /dataservice/device (2026-10-19), values kept;
// one hostile row appended.
const vmDeviceList = `{"data":[
 {"device-type":"vedge","personality":"vedge","host-name":"cEDGE-40","system-ip":"10.255.255.40","device-model":"vedge-CSR-1000v","board-serial":"6195696D","uuid":"CSR-BADCECC2-6CDC-1876-0072-0F9EAE28D879","site-id":"40","version":"17.03.02.0.3785","reachability":"reachable","state":"green","lastupdated":1792296433015},
 {"device-type":"vedge","personality":"vedge","host-name":"vEdge-20","system-ip":"10.255.255.20","device-model":"vedge-cloud","board-serial":"379CDF7B","uuid":"ff39e75a-8ee5-a214-6d15-3985fc7a9273","site-id":20,"version":"20.6.1","reachability":"unreachable","state":"red","lastupdated":1792296433015},
 {"device-type":"vsmart","personality":"vsmart","host-name":"vSmart","system-ip":"10.255.255.2","device-model":"vsmart","board-serial":"2700000004E668BCB9BAD5FDA5000000000004","site-id":"250","version":"20.6.1","reachability":"reachable","state":"green","lastupdated":1792296433015},
 {"device-type":"vedge","host-name":"evil\u0007<script>","system-ip":"not-an-ip","reachability":"reachable"}]}`

func TestValidateControllerDevice(t *testing.T) {
	ok := func(d ControllerDevice) ControllerDevice {
		t.Helper()
		v, good := ValidateControllerDevice(d)
		if !good {
			t.Fatalf("rejected %+v", d)
		}
		return v
	}
	bad := func(d ControllerDevice) {
		t.Helper()
		if _, good := ValidateControllerDevice(d); good {
			t.Fatalf("accepted %+v", d)
		}
	}
	bad(ControllerDevice{KeyKind: KeySystemIP, Key: "10.255.255.999"})
	bad(ControllerDevice{KeyKind: KeySerial, Key: "SN 1; DROP"})
	bad(ControllerDevice{KeyKind: KeyNone, Key: "uuid-123"}) // an opaque id is not an inventory identity
	bad(ControllerDevice{KeyKind: KeyName, Key: "   "})
	v := ok(ControllerDevice{KeyKind: KeySystemIP, Key: " 10.0.0.1 ", Name: "edge\u0000-1\n", MgmtAddr: "nope", Serial: "AB-12 34",
		Model: strings.Repeat("m", 500), Reachable: "REACHABLE", Aliases: map[string]string{"a": "1", "": "x", "b": ""}})
	if v.Key != "10.0.0.1" || v.Name != "edge-1" || v.MgmtAddr != "" || v.Serial != "" || len(v.Model) != maxDeviceFieldLen || v.Reachable != "reachable" {
		t.Fatalf("not normalised: %+v", v)
	}
	if len(v.Aliases) != 1 || v.Aliases["a"] != "1" {
		t.Fatalf("aliases %v", v.Aliases)
	}
	if v := ok(ControllerDevice{KeyKind: KeySerial, Key: "Q2XX-ABCD-1234"}); v.Key != "Q2XX-ABCD-1234" {
		t.Fatal(v.Key)
	}
}

func TestValidateSnapshotDropsInvalidAndDuplicateRows(t *testing.T) {
	in := []ControllerDevice{
		{KeyKind: KeySystemIP, Key: "10.0.0.1", Name: "a"},
		{KeyKind: KeySystemIP, Key: "10.0.0.1", Name: "dup"},
		{KeyKind: KeySystemIP, Key: "bogus"},
		{KeyKind: KeySystemIP, Key: "10.0.0.2", Name: "b"},
	}
	out := ValidateSnapshot(in)
	if len(out) != 2 || out[0].Name != "a" || out[1].Name != "b" {
		t.Fatalf("%+v", out)
	}
	big := make([]ControllerDevice, 0, maxControllerDevices+5)
	for i := 0; i < maxControllerDevices+5; i++ {
		big = append(big, ControllerDevice{KeyKind: KeySerial, Key: "S" + strings.Repeat("0", 1) + itoaTest(i)})
	}
	if n := len(ValidateSnapshot(big)); n != maxControllerDevices {
		t.Fatalf("snapshot not capped: %d", n)
	}
}

func itoaTest(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{digits[i%10]}, b...)
		i /= 10
	}
	return string(b)
}

func TestVManageInventoryEmitsTheDeviceSnapshot(t *testing.T) {
	b, err := VManageAutoTransformer{}.TransformStream("t-retail", "int-vm", "inventory", []byte(vmDeviceList))
	if err != nil {
		t.Fatal(err)
	}
	if b.Devices == nil {
		t.Fatal("an inventory payload must report a snapshot (non-nil Devices)")
	}
	byKey := map[string]ControllerDevice{}
	for _, d := range b.Devices {
		byKey[d.Key] = d
	}
	if len(b.Devices) != 3 {
		t.Fatalf("%d devices — want the two edges and the controller, the non-IP row dropped", len(b.Devices))
	}
	e := byKey["10.255.255.40"]
	if !e.Managed || e.Role != "edge" || e.Name != "cEDGE-40" || e.Model != "vedge-CSR-1000v" || e.OSVersion != "17.03.02.0.3785" ||
		e.SiteID != "40" || e.MgmtAddr != "10.255.255.40" || e.KeyKind != KeySystemIP || e.TenantID != "t-retail" || e.IntegrationID != "int-vm" {
		t.Fatalf("edge %+v", e)
	}
	if e.Serial != "" || e.Aliases["board_serial"] != "6195696D" || e.Aliases["uuid"] == "" {
		t.Fatalf("board-serial must be an alias, not a claimed chassis serial: %+v", e)
	}
	if byKey["10.255.255.20"].SiteID != "20" || byKey["10.255.255.20"].Reachable != "unreachable" {
		t.Fatalf("numeric site-id / reachability: %+v", byKey["10.255.255.20"])
	}
	if c := byKey["10.255.255.2"]; c.Managed || c.Role != "controller" {
		t.Fatalf("vSmart is the controller's own node, not a managed device: %+v", c)
	}
	// The existing states are still produced alongside.
	if len(b.States) == 0 {
		t.Fatal("inventory states lost")
	}
}

// Devices pass the pipeline validated and are never canonicalised: they ARE
// the identities the controller→inventory join resolves to.
func TestPipelineValidatesAndNeverCanonicalisesDevices(t *testing.T) {
	r := &mapResolver{m: map[string]string{"t-retail|10.255.255.40": "cedge-40-b99e47eb"}}
	p := NewPipeline(64)
	p.Resolver, p.KeyKind = r, KeySystemIP
	out := p.Route(Batch{Devices: []ControllerDevice{
		{TenantID: "t-retail", KeyKind: KeySystemIP, Key: "10.255.255.40", Name: "cEDGE-40"},
		{TenantID: "t-retail", KeyKind: KeySystemIP, Key: "junk"},
	}})
	if len(out.Devices) != 1 || out.Devices[0].Key != "10.255.255.40" {
		t.Fatalf("%+v", out.Devices)
	}
	if out := p.Route(Batch{}); out.Devices != nil {
		t.Fatal("a payload with no inventory must not report a snapshot")
	}
}

func runInventory(t *testing.T, body string, code int, streams ...string) RunResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			_, _ = w.Write([]byte(`{"token":"jwt-1"}`)) // discard: test server write to a live client
		case "/dataservice/device":
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body)) // discard: test server write to a live client
		case "/dataservice/alarms":
			_, _ = w.Write([]byte(`{"data":[]}`)) // discard: test server write to a live client
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	conn, _ := NewRegistry().Get("vmanage")
	cfg := IntegrationConfig{Tenant: "t-retail", IntegrationID: "int-vm", Vendor: "vmanage", BaseURL: srv.URL,
		Streams: streams, Creds: Credentials{Username: "ro", Password: "pw"}}
	res, _, err := RunPollSession(context.Background(), conn, cfg, NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry()), NewMemCheckpoints(), NewPipeline(1000), Session{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRunPollMarksOnlyACleanInventorySnapshotComplete(t *testing.T) {
	ok := runInventory(t, vmDeviceList, 200, "alarms", "inventory")
	if !ok.Routed.DevicesComplete || len(ok.Routed.Devices) != 3 {
		t.Fatalf("clean inventory: complete=%v devices=%d", ok.Routed.DevicesComplete, len(ok.Routed.Devices))
	}
	if r := runInventory(t, `{"data":[`, 200, "inventory"); r.Routed.DevicesComplete {
		t.Fatal("an unreadable inventory payload must not count as a complete snapshot")
	}
	if r := runInventory(t, `nope`, 500, "inventory"); r.Routed.DevicesComplete || r.Routed.Devices != nil {
		t.Fatalf("a failed inventory poll must not count as a snapshot: %+v", r.Routed)
	}
	if r := runInventory(t, vmDeviceList, 200, "alarms"); r.Routed.DevicesComplete || r.Routed.Devices != nil {
		t.Fatal("a cycle with no inventory stream has no snapshot")
	}
	// An EMPTY but clean list is a complete snapshot (the controller manages
	// nothing) — the store decides what an empty snapshot may delete.
	if r := runInventory(t, `{"data":[]}`, 200, "inventory"); !r.Routed.DevicesComplete || len(r.Routed.Devices) != 0 {
		t.Fatalf("empty clean snapshot: %+v", r.Routed)
	}
}
