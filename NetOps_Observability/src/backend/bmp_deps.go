// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bmp_deps.go — the wiring for internal/bmp (the BGP Monitoring Protocol
// receiver, frontend-wave item 10's "live BGP feed").
//
// internal/bmp holds NO ambient authority: it cannot read the environment,
// reach the inventory, decide who a caller is, or emit a log line except
// through the Deps assembled here. Every collaborator below is the SAME
// primitive the rest of the platform uses for that job — deliberately reused
// rather than re-derived, because a second implementation of tenant scoping is
// a second thing that can silently be wrong:
//
//	Authz         → s.requirePerm(infrastructure:read) + principalTenant
//	ResolveDevice → s.discovery.Devices() + deviceTenant (the SAME inventory
//	                and the SAME tenant-of-a-device rule the API uses)
//	OnAnnounce    → the bgpwatch sighting register (bgp_alerts.go), so a bogon
//	                a router just announced is visible immediately rather than
//	                on the evaluator's next tick
//	Log*          → applog (structured, §10)
//
// The module is READ-ONLY toward the network: it accepts a feed a router
// pushes, and configures nothing on any device. See internal/bmp/doc.go for
// the honesty contract (what a BMP feed is and is NOT).

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"netops/backend/internal/bmp"
)

// errUnsupportedBMPGate is the fail-closed answer to a gate the wiring does not
// map. It is a programming error, never a reason to serve the read.
var errUnsupportedBMPGate = errors.New("unsupported gate")

// buildBMP assembles the module. It returns an error rather than a half-wired
// API: bmp.New refuses an incomplete Deps, and a nil *API answers 404 on every
// route and starts no listener, so a failure here is dormant, never unscoped.
func (s *server) buildBMP() (*bmp.API, error) {
	return bmp.New(bmp.Deps{
		Now:           time.Now,
		ListenAddr:    envOr(bmp.EnvListen, bmp.DefaultListen),
		ResolveDevice: s.bmpResolveDevice,
		Authz:         s.bmpAuthz,
		Metrics:       bmp.NewMetrics(),
		// The bogon SIGHTING bridge (§10: a fact the receiver already has must
		// not wait five minutes to become observable). Nil-safe on both ends —
		// the adapter returns immediately when the evaluator is off — and read
		// at call time, so the construction ORDER of the two modules in main.go
		// does not matter.
		OnAnnounce: s.bgpWatchNoteBMPAnnounce,
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogInfo:    func(m string, f map[string]any) { logInfo("bmp", m, f) },
		LogWarn:    func(m string, f map[string]any) { logWarn("bmp", m, f) },
		LogError:   func(m string, f map[string]any) { logError("bmp", m, f) },
	})
}

// bmpAuthz maps the module's single gate onto the RBAC model. A BMP feed is
// per-tenant DATA — one customer's routing table, pushed by one customer's
// router — so it is requirePerm + a tenant filter, NOT a platform gate
// (§3a rule 3). Every route in the module is a READ; there is no write surface,
// and nothing here can configure a device.
func (s *server) bmpAuthz(w http.ResponseWriter, r *http.Request, gate bmp.Gate) (bmp.Principal, bool) {
	if gate != bmp.GateRead {
		// The module declares exactly one gate. An unknown gate is a wiring bug,
		// and the safe answer to a gate we cannot map is refusal.
		writeError(w, http.StatusForbidden, errUnsupportedBMPGate)
		return bmp.Principal{}, false
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return bmp.Principal{}, false
	}
	tenant, cross := principalTenant(claims)
	return bmp.Principal{Tenant: tenant, Cross: cross, Subject: claims.Sub}, true
}

// bmpResolveDevice attributes an inbound BMP session to a device and its
// OWNING TENANT (§3a rule 2: the owner is stamped from the inventory row, never
// from anything the peer said — a router does not know about our tenancy model
// and must never be able to assert one).
//
// A source that matches no device row resolves to ok=false, and the module
// closes the connection. That refusal is the whole point: admitting an
// unattributable feed as tenant "" would pool one customer's routing table into
// the global bucket that every tenant-less read can see.
func (s *server) bmpResolveDevice(addr netip.Addr) (deviceID, tenant string, ok bool) {
	if s.discovery == nil {
		return "", "", false
	}
	want := addr.Unmap()
	for _, d := range s.discovery.Devices() {
		a, err := netip.ParseAddr(strings.TrimSpace(d.Address))
		if err != nil {
			continue
		}
		if a.Unmap() != want {
			continue
		}
		t := deviceTenant(d)
		if t == "" {
			// A device row with no tenant is platform-owned inventory. It is a
			// legitimate row, but it is not an attribution: refuse rather than
			// store a customer's routing feed under no tenant at all.
			return "", "", false
		}
		return d.ID, t, true
	}
	return "", "", false
}

// The receiver is NOT started from here. Its one launch site is the composition
// root (main.go, the BMP block), where it is registered on the drain group as
// `workers.start("bmp-receiver", …)` — visible to the shutdown drift guard and
// WAITED FOR at shutdown. A helper here would hide the launch from that guard
// and buy nothing: bmp.API.Run is nil-safe, so a flag-off deployment that never
// reaches the launch site starts no goroutine and binds no port.
