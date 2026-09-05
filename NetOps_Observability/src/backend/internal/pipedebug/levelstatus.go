package pipedebug

// levelstatus.go — the READ side of /api/debug/loglevel.
//
// WHY A READ SIDE EXISTS. Raising a module to debug is bounded and
// self-reverting, but an operator who armed it still has to be able to SEE what
// is raised and when it comes back down — from the GUI, where the four
// `netops_debug_*` gauges are not visible (they are the watchdog's view, and
// the watchdog is deliberately outside the product).
//
// HONESTY IS THE WHOLE CONTRACT of this file, and it has three grades:
//
//   - `live`  — this process owns the switch and is reporting the switch itself
//     (today: the api's own level).
//   - `last-request` — the switch lives in ANOTHER process (correlation, via
//     its sidecar). We report the last change we asked for and when it said it
//     would revert, labelled as such. It is not a reading of that process.
//   - `unknown` — nothing has been asked and there is nothing to read.
//
// A module that cannot be switched at runtime at all reports switchable:false
// with the same reason the PUT returns, so the panel and the action agree.

import (
	"net/http"
	"sync"
	"time"
)

// LevelState is one module's row on the status panel.
type LevelState struct {
	Module Module `json:"module"`
	// Level is the level in force where it can be read, or the level of the
	// last change requested through this api. Empty when neither is known.
	Level Level `json:"level,omitempty"`
	// RevertAt is when an armed auto-revert fires. Zero = nothing armed.
	RevertAt time.Time `json:"revert_at,omitempty"`
	// Switchable reports whether PUT /api/debug/loglevel can move this module.
	Switchable bool `json:"switchable"`
	// Source is `live`, `last-request` or `unknown` — see the file comment.
	Source string `json:"source"`
	// Reason carries the honest explanation for a module that cannot be
	// switched, or for a source that is not a live reading.
	Reason string `json:"reason,omitempty"`
	// Service is the compose service that runs the module, so an operator can
	// go and read its container logs directly.
	Service string `json:"service,omitempty"`
}

// LevelStatus is GET /api/debug/loglevel.
type LevelStatus struct {
	Modules []LevelState `json:"modules"`
	// The caps, served with the state so the GUI does not hard-code them.
	MaxWindowSeconds     int `json:"max_window_seconds"`
	DefaultWindowSeconds int `json:"default_window_seconds"`
}

// Sources for LevelState.Source.
const (
	LevelSourceLive        = "live"
	LevelSourceLastRequest = "last-request"
	LevelSourceUnknown     = "unknown"
)

// IngressLevelReason is the honest answer for syslog-ng: its level is read from
// a config file at (re)start, and restarting the ingest edge during an incident
// is not an acceptable debug action.
const IngressLevelReason = "syslog-ng's level is set in its config file and applied at (re)start; this deployment has no restart-free way to change it, and restarting the ingest edge during an incident is not an acceptable debug action"

// lastLevels remembers what this api last ASKED another process to do, so the
// status route can report it as such. It is deliberately not a cache of the
// other process's state: nothing here is presented as a reading.
type lastLevels struct {
	mu sync.Mutex
	by map[Module]LevelChange
}

func (l *lastLevels) record(c LevelChange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[Module]LevelChange{}
	}
	l.by[c.Module] = c
}

func (l *lastLevels) get(m Module) (LevelChange, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	c, ok := l.by[m]
	return c, ok
}

// levelCapability answers, for one module, whether this build can move its
// level and — when it cannot — why. It is the SAME table setLevel dispatches
// on, so the panel can never advertise a switch the action does not have.
func (a *API) levelCapability(m Module) (bool, string) {
	switch m {
	case ModuleAPI:
		if a.deps.SetAPILevel == nil {
			return false, "the API log-level seam is not wired into this build"
		}
		return true, ""
	case ModuleCorrelation:
		if a.deps.CorrLogLevel == nil {
			return false, "no correlation debug-sidecar seam is wired into this build"
		}
		return true, ""
	case ModuleVector:
		if a.deps.VectorLogLevel == nil {
			return false, VectorLevelReason
		}
		return true, ""
	case ModuleRouter:
		return false, VectorLevelReason
	case ModuleIngress:
		return false, IngressLevelReason
	default:
		return false, "this module has no log-level control"
	}
}

// levelStatus renders every module's row.
func (a *API) levelStatus() LevelStatus {
	out := LevelStatus{
		Modules:              make([]LevelState, 0, len(Modules)),
		MaxWindowSeconds:     int(MaxWindow.Seconds()),
		DefaultWindowSeconds: int(DefaultWindow.Seconds()),
	}
	for _, m := range Modules {
		switchable, reason := a.levelCapability(m)
		svc, _ := ComposeService(m)
		st := LevelState{Module: m, Switchable: switchable, Reason: reason, Service: svc, Source: LevelSourceUnknown}
		if lr, ok := a.deps.LevelReaders[m]; ok && lr != nil {
			st.Level = lr.Current()
			st.RevertAt = lr.RevertAt()
			st.Source = LevelSourceLive
		} else if c, ok := a.lastLevel.get(m); ok {
			st.Level = c.Level
			st.RevertAt = c.RevertAt
			st.Source = LevelSourceLastRequest
			if st.Reason == "" {
				st.Reason = "the switch lives in that module's own process; this is the last change requested through this api, not a reading of it"
			}
		}
		out.Modules = append(out.Modules, st)
	}
	return out
}

// HandleLogLevelStatus serves GET /api/debug/loglevel. It is reached through
// HandleLogLevel, which owns the path.
func (a *API) HandleLogLevelStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := a.deps.Authz(w, r)
	if !ok {
		return
	}
	// Read-only, but audited like the rest of the family: knowing which module
	// somebody has at debug is operationally sensitive on its own.
	a.audit(r, p.Tenant, "debug.loglevel.status", map[string]any{"modules": len(Modules)})
	a.deps.WriteJSON(w, http.StatusOK, a.levelStatus())
}
