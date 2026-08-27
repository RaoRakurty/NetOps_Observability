package hardening

import (
	"context"
	"sort"
)

// ConfigSource yields a device's running-configuration text. It is the narrow
// input seam between this engine and config capture (T-config): the engine never
// reaches for a config itself, it asks this interface. ok=false means "no config
// on file for this device" — the engine FAILS CLOSED on that (StatusUnknown),
// never a Pass.
//
// TODO(T-config): wire a real ConfigSource backed by the SSH-gateway config
// capture + sealed config store. Until then MemConfigSource is the only impl and
// is used by tests and any dormant, flag-off call site.
type ConfigSource interface {
	// RunningConfig returns the raw running-config for a device. ok=false when
	// no config is available (not yet captured / capture failed). A non-nil
	// error is a transport/store failure distinct from "absent".
	RunningConfig(ctx context.Context, deviceID string) (raw string, ok bool, err error)
}

// SeamInfo is one interface's seam attribution — which named seam an interface
// faces and whether that seam is UNTRUSTED (internet / ISP / any zone the device
// must assume hostile). It is the minimal slice of the seam model the exposure
// evaluator needs.
type SeamInfo struct {
	SeamID    string // canonical seam id
	SeamType  string // e.g. "ISP", "internet", "mgmt", "campus"
	Interface string // the device interface facing this seam
	Untrusted bool   // internet-facing / untrusted zone
}

// SeamResolver maps a device to the seams its interfaces face. It is the second
// narrow input seam: the exposure evaluator asks "does this device touch an
// untrusted seam, and via which interface" without knowing how the seam model is
// stored. ok=false means the seam model has NO data for the device — the engine
// FAILS CLOSED on exposure verdicts for that device (StatusUnknown), because it
// cannot prove non-exposure.
//
// TODO(T-config): wire a real SeamResolver onto the live seam inventory
// (internal/seam) + interface→seam attribution. MemSeamResolver is the stub.
type SeamResolver interface {
	// DeviceSeams returns the seam attributions for a device's interfaces.
	// ok=false → the seam model has no data for the device (fail closed).
	DeviceSeams(ctx context.Context, deviceID string) (seams []SeamInfo, ok bool, err error)
}

// MemConfigSource is an in-memory ConfigSource for tests and dormant call sites:
// a device-id → running-config map. A device absent from the map returns
// ok=false (the fail-closed "no config" path).
type MemConfigSource map[string]string

// RunningConfig implements ConfigSource.
func (m MemConfigSource) RunningConfig(_ context.Context, deviceID string) (string, bool, error) {
	raw, ok := m[deviceID]
	return raw, ok, nil
}

// MemSeamResolver is an in-memory SeamResolver for tests and dormant call sites:
// a device-id → []SeamInfo map. A device absent from the map returns ok=false
// (the fail-closed "no seam data" path).
type MemSeamResolver map[string][]SeamInfo

// DeviceSeams implements SeamResolver.
func (m MemSeamResolver) DeviceSeams(_ context.Context, deviceID string) ([]SeamInfo, bool, error) {
	seams, ok := m[deviceID]
	if !ok {
		return nil, false, nil
	}
	out := make([]SeamInfo, len(seams))
	copy(out, seams)
	return out, true, nil
}

// pickUntrusted returns the "worst" untrusted seam (deterministically: the
// lowest SeamID among untrusted seams) and whether one exists.
func pickUntrusted(seams []SeamInfo) (SeamInfo, bool) {
	var found []SeamInfo
	for _, s := range seams {
		if s.Untrusted {
			found = append(found, s)
		}
	}
	if len(found) == 0 {
		return SeamInfo{}, false
	}
	sort.Slice(found, func(i, j int) bool { return found[i].SeamID < found[j].SeamID })
	return found[0], true
}

// pickTrusted returns a representative trusted (mgmt / non-untrusted) seam and
// whether one exists — used to attribute the informational, non-exposed verdict.
func pickTrusted(seams []SeamInfo) (SeamInfo, bool) {
	var found []SeamInfo
	for _, s := range seams {
		if !s.Untrusted {
			found = append(found, s)
		}
	}
	if len(found) == 0 {
		return SeamInfo{}, false
	}
	sort.Slice(found, func(i, j int) bool { return found[i].SeamID < found[j].SeamID })
	return found[0], true
}
