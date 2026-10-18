// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "sync"

// identity.go — one physical device, one entity.
//
// A controller names a device by ITS key (vManage: system-ip, Meraki: serial,
// Versa: appliance name). Correlix inventory names it by the discovery id
// (<sysName>-<hash>) that every syslog, trap, flow and SNMP series already
// carries. Without a join, an outage the controller and the device both report
// is two entities and two incidents.
//
// The join happens once, at ingest, before Route: events, states and metric
// labels all leave the runtime carrying the inventory id, for every vendor,
// with no change on the bus or in correlation. The controller's own key is
// kept beside it (controller_device), and state EntityKeys are never rewritten
// so flap history survives a mapping change.
//
// Matching is tenant-strict and abstains when unsure: a controller key that
// matches no device, or more than one, keeps its own key. A wrong merge hides
// an outage on another device; an unmatched one only costs a second entity.

// KeyKind is what a connector's native DeviceID is.
type KeyKind string

const (
	KeyNone     KeyKind = ""          // opaque (a controller UUID, an AP MAC): not resolvable
	KeySystemIP KeyKind = "system_ip" // SD-WAN overlay system-ip
	KeySerial   KeyKind = "serial"    // chassis serial
	KeyName     KeyKind = "name"      // device hostname
	KeyIP       KeyKind = "ip"        // a device address
)

// DeviceResolver maps a controller's key for a device to the inventory id of
// a device the SAME tenant owns. name is the controller's hostname for it, ""
// when unknown. ok=false means "no unique match" — never a guess.
type DeviceResolver interface {
	ResolveDevice(tenant string, kind KeyKind, key, name string) (id string, ok bool)
}

// deviceNameMemoCap bounds the key→hostname memo one pipeline keeps.
const deviceNameMemoCap = 8192

// deviceNames remembers the hostname a controller reported for a key (from
// inventory states and events), so a metric — which carries only the key —
// can still be matched by name.
type deviceNames struct {
	mu sync.Mutex
	m  map[string]string
}

func (d *deviceNames) learn(key, name string) {
	if key == "" || name == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]string{}
	}
	if _, ok := d.m[key]; !ok && len(d.m) >= deviceNameMemoCap {
		return // bounded: past the cap a new key is matched by key alone
	}
	d.m[key] = name
}

func (d *deviceNames) get(key string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[key]
}

// canonicalize rewrites a batch's device references to inventory ids.
func canonicalize(r DeviceResolver, kind KeyKind, names *deviceNames, b Batch) Batch {
	if r == nil || kind == KeyNone {
		return b
	}
	for _, s := range b.States {
		if n, _ := s.Data["device_name"].(string); n != "" { // discard: a non-string name is no name
			names.learn(s.DeviceID, n)
		}
	}
	for _, e := range b.Events {
		names.learn(e.DeviceID, e.DeviceName)
	}
	resolve := func(tenant, key string) (string, bool) {
		if key == "" {
			return "", false
		}
		return r.ResolveDevice(tenant, kind, key, names.get(key))
	}

	events := make([]ControllerEvent, len(b.Events))
	for i, e := range b.Events {
		// The dedupe key is fixed from the NATIVE identity first, so a mapping
		// that appears (or flips) between polls never re-emits an old event.
		if e.DedupeKey == "" {
			e.DedupeKey = DedupeKey(e)
		}
		if id, ok := resolve(e.TenantID, e.DeviceID); ok && id != e.DeviceID {
			hints := make(map[string]string, len(e.CorrelationHints)+1)
			for k, v := range e.CorrelationHints {
				hints[k] = v
			}
			hints["controller_device_id"] = e.DeviceID
			e.CorrelationHints = hints
			e.DeviceID = id
		}
		events[i] = e
	}
	states := make([]ControllerState, len(b.States))
	for i, s := range b.States {
		if id, ok := resolve(s.TenantID, s.DeviceID); ok && id != s.DeviceID {
			data := make(map[string]any, len(s.Data)+1)
			for k, v := range s.Data {
				data[k] = v
			}
			data["controller_device_id"] = s.DeviceID
			s.Data = data
			s.DeviceID = id // EntityKey stays native: flap history is per controller entity
		}
		states[i] = s
	}
	metrics := make([]ControllerMetric, len(b.Metrics))
	for i, m := range b.Metrics {
		if key := m.Tags["device"]; key != "" {
			if id, ok := resolve(m.TenantID, key); ok && id != key {
				tags := make(map[string]string, len(m.Tags)+1)
				for k, v := range m.Tags {
					tags[k] = v
				}
				tags["controller_device"] = key
				tags["device"] = id
				m.Tags = tags
			}
		}
		metrics[i] = m
	}
	b.Events, b.States, b.Metrics = events, states, metrics
	return b
}
