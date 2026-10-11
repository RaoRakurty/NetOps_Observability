// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/featureflags"
	"netops/backend/internal/platformdb"
)

// feature_flags.go — the platform-admin Features page (tracker 348; owner
// 2026-10-05: every feature switchable from the GUI, customers never edit
// .env, env = install defaults only). The registry is internal/featureflags;
// this file is the spec table, the persistence adapter and the two routes.
//
// WHAT IS NOT ON THE PAGE, and why (stated so nobody adds it casually):
//   - controls, not capabilities — FEATURE_SEALED_FIELDS (boot-fatal when
//     custody is missing, and turning it off silently stops encrypting), TLS
//     posture, the store backend, BROKER_URLS, VMALERT_NOTIFIER_FLAG,
//     AI_TOOLS_ALL_TENANTS (cross-tenant reach). No saved switch may stop the
//     api from booting, or the page could not undo it.
//   - flags read by OTHER containers (the correlation engine's CORR_*,
//     ENABLE_FLOW_CORRELATION, gnmic's ENABLE_GNMI_CORRELATION, the prober's
//     FEATURE_TRACEROUTE / ACTIVE_PROBE / STAMP_REFLECTOR / DEM / SYNTHETICS /
//     WAN_ECHO): the api cannot apply them; delivering them to those
//     containers is a follow-up, not a switch that pretends.
//   - settings already managed on their own pages (notification channels,
//     ITSM, SNMP discovery): one place per setting.
//   - the AI switches: what an install that already holds a provider key
//     should default to is an owner decision (tracker 348).
//   - ENABLE_REPORT_SCHEDULER: a flag-gated log.Fatalf path at start.

const featureFlagsKey = "/data/feature_flags.json"

// featureSpecs is the switchable set. Apply class and semantics follow how
// each flag is ACTUALLY read (verified 2026-10-11): per request/poll → Live;
// read once at start (pool.Enable, a worker, a bound port, routes registered
// only when a module is built) → Restart. A flag read both ways is Restart,
// so the page never shows a value that is not running.
func featureSpecs() []featureflags.Spec {
	const (
		collect   = "Collection"
		discover  = "Discovery"
		routing   = "Routing"
		access    = "Configuration and device access"
		integrate = "Integrations and automation"
		analytics = "Analytics"
	)
	live, restart := featureflags.ApplyLive, featureflags.ApplyRestart
	return []featureflags.Spec{
		{Env: "ENABLE_SNMP_COLLECTION", Label: "SNMP polling", Group: collect, Apply: restart, Help: "Poll devices over SNMP v2c and v3."},
		{Env: "ENABLE_SNMP_METRICS", Label: "SNMP metrics", Group: collect, Apply: restart, Help: "Collect interface, CPU, memory and routing metrics over SNMP."},
		{Env: "ENABLE_GNMI_COLLECTION", Label: "gNMI streaming telemetry", Group: collect, Apply: restart, Help: "Subscribe to gNMI telemetry on devices that support it."},
		{Env: "ENABLE_NETCONF_COLLECTION", Label: "NETCONF polling", Group: collect, Apply: restart, Help: "Read device state over NETCONF."},
		{Env: "FEATURE_SNMP_TRAPS", Label: "SNMP traps", Group: collect, Apply: restart, Help: "Receive SNMP traps from devices."},
		{Env: "FEATURE_PORT_DOM", Label: "Optics readings (DOM)", Group: collect, Apply: live, Help: "Read optical power, temperature and voltage per port."},
		{Env: "FEATURE_UNIFI", Label: "UniFi controller", Group: collect, Apply: restart, Risky: true, Help: "Read device health from a Ubiquiti UniFi controller."},

		{Env: "ENABLE_VENDOR_DETECTION", Label: "Vendor detection", Group: discover, Apply: restart, Help: "Identify vendor and OS from each device's system ID."},
		{Env: "ENABLE_LLDP_DISCOVERY", Label: "LLDP neighbours", Group: discover, Apply: restart, Help: "Learn neighbours from LLDP."},
		{Env: "ENABLE_CDP_DISCOVERY", Label: "CDP neighbours", Group: discover, Apply: restart, Help: "Learn neighbours from CDP."},
		{Env: "ENABLE_TUNNEL_DISCOVERY", Label: "Tunnels", Group: discover, Apply: restart, Help: "Discover IPsec, GRE and SD-WAN tunnels."},
		{Env: "ENABLE_SDWAN_OVERLAY", Label: "SD-WAN overlay", Group: discover, Apply: restart, Help: "Read SD-WAN tunnels and transports from SD-WAN edges."},
		{Env: "ENABLE_VRF_COLLECTION", Label: "VRFs and routing instances", Group: discover, Apply: restart, Help: "Read routing instances and their interfaces."},
		{Env: "ENABLE_BGPLS_DISCOVERY", Label: "BGP-LS topology", Group: discover, Apply: restart, Help: "Learn topology from BGP-LS."},

		{Env: "FEATURE_BGP_ALERTS", Label: "BGP alerts", Group: routing, Apply: restart, Help: "Watch prefixes and alert on hijacks and leaks."},
		{Env: "FEATURE_BGP_LIVE_FEED", Label: "Live BGP update feed", Group: routing, Apply: restart, Help: "Follow BGP updates in near real time."},
		{Env: "FEATURE_BMP", Label: "BMP listener", Group: routing, Apply: restart, Help: "Receive BGP Monitoring Protocol sessions from routers."},
		{Env: "FEATURE_PATH_GRAPH", Label: "Path graph", Group: routing, Apply: restart, Help: "Build the forwarding-path graph from path measurements."},
		{Env: "FEATURE_PATH_BASELINES", Label: "Path baselines", Group: routing, Apply: restart, Help: "Learn normal latency and loss per path."},

		{Env: "FEATURE_CONFIG_BACKUP", Label: "Configuration backup", Group: access, Apply: restart, Risky: true, Help: "Log in to devices to back up their configuration and detect drift."},
		{Env: "FEATURE_DEVICE_SSH", Label: "SSH to devices", Group: access, Apply: live, Risky: true, Help: "Open an SSH session to a device from the browser."},
		{Env: "FEATURE_PROTOCOL_DIAG_COLLECT", Label: "Run diagnostic commands", Group: access, Apply: live, Risky: true, Help: "Run read-only show commands on devices for troubleshooting."},
		{Env: "FEATURE_WIRELESS_ACTIONS", Label: "Wireless actions", Group: access, Apply: live, Risky: true, Help: "Allow actions that change wireless controllers."},
		{Env: "FEATURE_PACKET_CAPTURE", Label: "Packet capture", Group: access, Apply: restart, Risky: true, Help: "Capture packets on request."},

		{Env: "FEATURE_NMS_INTEGRATIONS", Label: "NMS integrations", Group: integrate, Apply: restart, Semantics: featureflags.OnUnlessFalse, Help: "Connect other network management systems."},
		{Env: "FEATURE_ITSM_INBOUND", Label: "Ticket updates from ITSM", Group: integrate, Apply: live, Risky: true, Help: "Accept ticket updates sent by your ITSM tool."},
		{Env: "FEATURE_ITSM_RECONCILE", Label: "Ticket reconciliation", Group: integrate, Apply: restart, Help: "Keep tickets and incidents in step."},
		{Env: "FEATURE_RCA_TICKETING", Label: "Tickets from root causes", Group: integrate, Apply: restart, Help: "Open tickets from confirmed root causes."},
		{Env: "FEATURE_PROCESSORS", Label: "Pipeline processors", Group: integrate, Apply: live, Help: "Show the per-tenant log processor editor."},

		{Env: "FEATURE_SECURITY_LANE", Label: "Security findings", Group: analytics, Apply: restart, Help: "Correlate security events with network faults."},
		{Env: "FEATURE_ACTIVE_VERIFICATION", Label: "Active verification", Group: analytics, Apply: restart, Help: "Test a suspected cause with safe, read-only checks."},
		{Env: "FEATURE_SVC_FLOW_ROLLUP", Label: "Service traffic totals", Group: analytics, Apply: restart, Help: "Roll flow traffic up per service every minute."},
	}
}

// kvFeatureStore persists the saved values in the platform key-value store
// (app_kv on Postgres, a file on the file backend). Not sealed: the values are
// not secret, and sealing would make every boot depend on secret custody.
type kvFeatureStore struct{ key string }

func (k kvFeatureStore) Load() ([]byte, error) { return platformdb.Load(k.key) }
func (k kvFeatureStore) Save(b []byte) error   { return platformdb.Save(k.key, b) }

// newFeatureRegistry builds and loads the registry. It runs before any reader
// of these flags (pool.Enable, the workers), so saved values are what start.
// A store failure is reported loudly and never stops the boot.
func newFeatureRegistry() *featureflags.Registry {
	reg := featureflags.New(featureSpecs(), featureflags.OSEnv{}, kvFeatureStore{key: featureFlagsKey})
	if err := reg.Load(); err != nil {
		logError("features", "saved feature settings could not be read — install values are in force and risky features are OFF until they load", errf(err))
	}
	return reg
}

// featureRow is one flag on the wire.
type featureRow struct {
	Env            string    `json:"env"`
	Label          string    `json:"label"`
	Group          string    `json:"group"`
	Help           string    `json:"help"`
	Apply          string    `json:"apply"`
	Risky          bool      `json:"risky"`
	Running        bool      `json:"running"`
	Desired        bool      `json:"desired"`
	RestartPending bool      `json:"restart_pending"`
	Source         string    `json:"source"`
	InstallValue   *bool     `json:"install_value"`
	UpdatedBy      string    `json:"updated_by,omitempty"`
	UpdatedAt      time.Time `json:"updated_at,omitempty"`
}

func toFeatureRow(st featureflags.State) featureRow {
	return featureRow{
		Env: st.Env, Label: st.Label, Group: st.Group, Help: st.Help, Apply: string(st.Apply), Risky: st.Risky,
		Running: st.Running, Desired: st.Desired, RestartPending: st.RestartPending, Source: string(st.Source),
		InstallValue: st.InstallValue, UpdatedBy: st.UpdatedBy, UpdatedAt: st.UpdatedAt,
	}
}

// restartSupervised: the api may restart itself only when something will
// start it again (compose restart policy / a Kubernetes Deployment). The
// installer, compose and the chart set CORRELIX_SUPERVISED=true.
func restartSupervised() bool { return os.Getenv("CORRELIX_SUPERVISED") == "true" }

func (s *server) featuresPayload() map[string]any {
	states := s.features.List()
	rows := make([]featureRow, 0, len(states))
	pending := false
	for _, st := range states {
		rows = append(rows, toFeatureRow(st))
		pending = pending || st.RestartPending
	}
	out := map[string]any{
		"features":         rows,
		"restart_pending":  pending,
		"can_restart":      restartSupervised(),
		"store_load_error": "",
	}
	if err := s.features.LoadError(); err != nil {
		out["store_load_error"] = "The saved feature settings could not be read when Correlix started. Install values are in force and risky features are off."
	}
	return out
}

// handlePlatformFeatures: GET the switchable set; PUT {env, value,
// acknowledge} to change one. Platform-global (§3a.3): requirePlatformAdmin,
// never a tenant admin; API keys are refused for changes.
func (s *server) handlePlatformFeatures(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	if s.features == nil {
		writeError(w, http.StatusServiceUnavailable, errors.New("feature settings are not available on this server"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.featuresPayload())
	case http.MethodPut:
		if strings.HasPrefix(claims.Sub, "apikey:") {
			writeError(w, http.StatusForbidden, errors.New("feature settings can only be changed from a signed-in session"))
			return
		}
		var body struct {
			Env         string `json:"env"`
			Value       *bool  `json:"value"`
			Acknowledge string `json:"acknowledge"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil || body.Value == nil {
			writeError(w, http.StatusBadRequest, errors.New("send {\"env\": <feature>, \"value\": true|false}"))
			return
		}
		before, known := s.features.Get(body.Env)
		if !known {
			writeError(w, http.StatusBadRequest, featureflags.ErrUnknownFlag)
			return
		}
		if before.Risky && *body.Value && body.Acknowledge != before.Env {
			writeError(w, http.StatusBadRequest, featureflags.ErrAckRequired)
			return
		}
		// The trail is written BEFORE the change: a change the audit cannot
		// record does not happen.
		ev := AuditEvent{
			Actor: claims.Sub, Cross: true, Method: r.Method, Path: r.URL.Path, Status: http.StatusOK, Decision: "allow",
			Detail: map[string]any{"action": "feature_flag_set", "flag": before.Env, "from": before.Desired, "to": *body.Value, "apply": string(before.Apply)},
		}
		if err := s.audit.RecordStrict(ev); err != nil {
			writeError(w, http.StatusInternalServerError, errors.New("the change was not made: the audit trail could not record it"))
			return
		}
		_, after, err := s.features.Set(body.Env, *body.Value, body.Acknowledge, claims.Sub, time.Now())
		if err != nil {
			fail := ev
			fail.Status, fail.Decision = http.StatusInternalServerError, "error"
			fail.Detail = map[string]any{"action": "feature_flag_set", "flag": before.Env, "error": err.Error()}
			s.audit.Record(fail)
			status := http.StatusInternalServerError
			if errors.Is(err, featureflags.ErrAckRequired) || errors.Is(err, featureflags.ErrUnknownFlag) {
				status = http.StatusBadRequest
			}
			writeError(w, status, err)
			return
		}
		logInfo("features", "feature setting changed", map[string]any{"flag": after.Env, "to": *body.Value, "apply": string(after.Apply), "by": claims.Sub})
		writeJSON(w, http.StatusOK, map[string]any{"feature": toFeatureRow(after), "restart_pending": s.anyRestartPending()})
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or PUT"))
	}
}

func (s *server) anyRestartPending() bool {
	for _, st := range s.features.List() {
		if st.RestartPending {
			return true
		}
	}
	return false
}

// restartGate carries the restart request to Run and allows one request per
// five minutes per process.
type restartGate struct {
	mu   sync.Mutex
	last time.Time
	ch   chan struct{}
}

// handlePlatformRestart restarts the api so restart-class settings take
// effect: the graceful shutdown path runs (HTTP drain, worker drain), Run
// returns, the process exits 0 and its supervisor starts it again with the
// saved settings applied by Load. Refused when nothing supervises the process.
func (s *server) handlePlatformRestart(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePlatformAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, errors.New("POST only"))
		return
	}
	if strings.HasPrefix(claims.Sub, "apikey:") {
		writeError(w, http.StatusForbidden, errors.New("a restart can only be requested from a signed-in session"))
		return
	}
	if !restartSupervised() || s.restart == nil {
		writeError(w, http.StatusConflict, errors.New("this installation is not set up to restart itself; restart the Correlix service from the host"))
		return
	}
	g := s.restart
	g.mu.Lock()
	if !g.last.IsZero() && time.Since(g.last) < 5*time.Minute {
		g.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, errors.New("a restart was requested less than five minutes ago"))
		return
	}
	ev := AuditEvent{Actor: claims.Sub, Cross: true, Method: r.Method, Path: r.URL.Path, Status: http.StatusAccepted, Decision: "allow",
		Detail: map[string]any{"action": "platform_restart", "reason": "apply feature settings"}}
	if err := s.audit.RecordStrict(ev); err != nil {
		g.mu.Unlock()
		writeError(w, http.StatusInternalServerError, errors.New("the restart was not requested: the audit trail could not record it"))
		return
	}
	g.last = time.Now()
	g.mu.Unlock()
	logInfo("features", "restart requested to apply feature settings", map[string]any{"by": claims.Sub})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "restarting"})
	select {
	case g.ch <- struct{}{}:
	default: // a restart is already under way
	}
}
