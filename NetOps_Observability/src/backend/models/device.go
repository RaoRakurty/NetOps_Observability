// Package models holds the shared data types exchanged between subsystems
// and over the public HTTP API. Keep this package free of behaviour so it
// can be imported anywhere without creating dependency cycles.
package models

import "time"

// Device is the canonical representation of a managed network element.
type Device struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Vendor  string `json:"vendor,omitempty"`
	Model   string `json:"model,omitempty"`
	OS      string `json:"os,omitempty"`
	// Type — router|switch|firewall|load-balancer|ap|wlc|cloud-gw|generic.
	// SNMP-inferred from vendor/model/sysDescr (InferDeviceType), operator-overridable
	// via labels["device_type"]. Populated on-read by the devices API.
	Type              string `json:"type,omitempty"`
	PreferredProtocol string `json:"preferred_protocol,omitempty"`
	CredentialRef     string `json:"credential_ref,omitempty"`
	// CredentialActive — the profile actually answering (credential sentinel's
	// learned override); "" means the bound CredentialRef is in use. Populated
	// on-read by the devices API, never persisted.
	CredentialActive string            `json:"credential_active,omitempty"`
	TenantID         string            `json:"tenant_id,omitempty"` // owning tenant ("" = global/shared)
	Labels           map[string]string `json:"labels,omitempty"`
	Source           string            `json:"source"`
	LastSeen         time.Time         `json:"last_seen"`

	// Monitored — Correlix is CONFIGURED to collect telemetry from this device.
	// It is the licensed unit (entitlement.CeilingDevices counts monitored
	// devices, not inventory rows) and the collector pool polls only devices
	// that carry it.
	//
	// SERVER-STAMPED, NEVER PERSISTED and never read from a request body: the
	// device registry computes it from the operator's monitoring decision (or,
	// absent one, the device's provenance) on every read — the same
	// infer-on-read contract Type and CredentialActive follow. A client that
	// sends it is ignored.
	Monitored bool `json:"monitored"`
	// MonitorReason says WHY Monitored has the value it has, in one operator
	// sentence. Never silent: a device that is not collected from always says
	// what would change that.
	MonitorReason string `json:"monitor_reason,omitempty"`
	// MonitorMethods lists the per-device telemetry the device is configured
	// for (e.g. "snmp", "gnmi"). It is DISPLAY, not the count: several methods
	// on one device are still one monitored device.
	MonitorMethods []string `json:"monitor_methods,omitempty"`
}

// Metric is a single time-series sample emitted by a collector.
type Metric struct {
	DeviceID  string            `json:"device_id"`
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	Labels    map[string]string `json:"labels,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// Alert represents a fired alert ready for notification dispatch.
type Alert struct {
	ID          string            `json:"id"`
	Rule        string            `json:"rule"`
	Severity    string            `json:"severity"`
	DeviceID    string            `json:"device_id,omitempty"`
	Summary     string            `json:"summary"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	FiredAt     time.Time         `json:"fired_at"`
	ResolvedAt  *time.Time        `json:"resolved_at,omitempty"`
}
