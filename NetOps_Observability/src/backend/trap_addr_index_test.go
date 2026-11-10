// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"testing"

	"netops/backend/models"
)

// The receiver's index resolves unique interface addresses, keeps the last
// good index when the address registry is unread, and answers device ids only.
func TestTrapAddrIndexRebuild(t *testing.T) {
	devs := []models.Device{{ID: "cedge-81", Address: "192.168.222.106", TenantID: ""}, {ID: "acme-edge", Address: "10.1.0.1", TenantID: "acme"}}
	ok := func(context.Context) (map[string]map[string]string, error) {
		return map[string]map[string]string{"cedge-81": {"192.168.200.33": "GigabitEthernet3", "192.168.1.1": "Lo65528"}}, nil
	}
	ix := &trapAddrIndex{}
	if dev, hit := ix.resolve("192.168.200.33"); hit || dev != "" {
		t.Fatal("an index never built must resolve nothing")
	}
	if err := ix.rebuild(context.Background(), devs, ok); err != nil {
		t.Fatal(err)
	}
	if dev, hit := ix.resolve("192.168.200.33"); !hit || dev != "cedge-81" {
		t.Fatalf("interface address = %q,%v", dev, hit)
	}
	if _, hit := ix.resolve("192.168.1.1"); hit {
		t.Fatal("internal VPN loopback resolved")
	}
	bad := func(context.Context) (map[string]map[string]string, error) { return nil, errors.New("valkey down") }
	if err := ix.rebuild(context.Background(), devs, bad); err == nil {
		t.Fatal("an unread registry must be reported")
	}
	if dev, hit := ix.resolve("192.168.200.33"); !hit || dev != "cedge-81" {
		t.Fatal("an unread registry dropped the last good index")
	}
	fresh := &trapAddrIndex{}
	if err := fresh.rebuild(context.Background(), devs, bad); err == nil {
		t.Fatal("want error")
	}
	if dev, hit := fresh.resolve("10.1.0.1"); !hit || dev != "acme-edge" {
		t.Fatal("with no registry yet, management addresses still index")
	}
}
