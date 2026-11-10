// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"netops/backend/internal/ifbridge"
)

// if_rows_nms.go — the key-value IO of the interface bridge's NMS half and of
// the SNMP facts the merge needs beside the two published maps (tracker 387 PR
// 13a; internal/ifbridge holds the rules).
//
// FetchIfAddrMap and FetchIfIndexMap stay the SNMP collector's maps exactly.
// The api merges them with the NMS rows (if_bridge.go there); the merge needs a
// canonical port comparison that lives in the api, and one place doing it is
// one place to get it right.

const (
	// nmsIfRowsKey holds the NMS rows (ifbridge.State), written by the api every
	// minute. Its TTL outlives ifbridge.MaxAge by a day, like ifRowStateKey: the
	// api ages rows out itself, and a dead api must still let them self-expire.
	nmsIfRowsKey      = "netops:topology:ifrows_nms"
	nmsIfRowsTTLSec   = ifRowStateTTLSec
	ifAliasKey        = "netops:topology:ifalias"
	ifAliasTTLSec     = ifRowPublishTTLSec
	maxIfAliasDevices = 20000
)

// PublishNMSIfRows stores the NMS rows. No key-value channel on this
// deployment is not an error: nothing is stored, and the bridge's readers, who
// read the SNMP maps over the same channel, have no bridge at all there.
func PublishNMSIfRows(ctx context.Context, st ifbridge.State) error {
	if RedisAddr() == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", nmsIfRowsKey, err)
	}
	return redisSetEX(ctx, nmsIfRowsKey, string(b), nmsIfRowsTTLSec)
}

// FetchNMSIfRows reads the NMS rows. Absent → an empty state, nil error; an
// unread channel or an undecodable payload → an error (tracker 307: we authored
// it, so a decode failure is corrupt evidence, not absent evidence). A payload
// of another version is treated as absent. The state is NOT sanitized here:
// the reader owns the clock (ifbridge.State.Sanitize).
func FetchNMSIfRows(ctx context.Context) (ifbridge.State, error) {
	var st ifbridge.State
	if err := redisGetJSON(ctx, "NMS interface rows", nmsIfRowsKey, &st); err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return ifbridge.NewState(), nil
		}
		return ifbridge.NewState(), err
	}
	if st.Version != ifbridge.StateVersion || st.Devices == nil {
		return ifbridge.NewState(), nil
	}
	return st, nil
}

// SNMPIfRowAges is each device's walk time (unix ms) behind the published
// address and ifIndex maps, from the collector's retained-row state.
type SNMPIfRowAges struct {
	Addr, Index map[string]int64
}

// FetchSNMPIfRowAges reads the retained-row state for the walk times the merge
// compares against. Absent, unconfigured or of another version → empty ages
// and nil (every SNMP row is then of unknown age); unread → an error.
func FetchSNMPIfRowAges(ctx context.Context) (SNMPIfRowAges, error) {
	out := SNMPIfRowAges{Addr: map[string]int64{}, Index: map[string]int64{}}
	var st ifRowState
	if err := redisGetJSON(ctx, "retained interface rows", ifRowStateKey, &st); err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return out, nil
		}
		return out, err
	}
	if st.Version != ifRowStateVersion {
		return out, nil
	}
	for id, e := range st.Devices {
		if e == nil {
			continue
		}
		if e.Addr.At > 0 {
			out.Addr[id] = e.Addr.At
		}
		if e.Index.At > 0 {
			out.Index[id] = e.Index.At
		}
	}
	return out, nil
}

// FetchIfAliasMap reads the SNMP ifAlias map (deviceID → ifIndex → ifAlias).
// Absent → empty map, nil error; unread or undecodable → an error.
func FetchIfAliasMap(ctx context.Context) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	if err := redisGetJSON(ctx, "ifAlias map", ifAliasKey, &out); err != nil {
		if errors.Is(err, ErrNotConfigured) {
			return map[string]map[string]string{}, nil
		}
		return map[string]map[string]string{}, err
	}
	return out, nil
}

// ifAliasRows keeps each device's last-read ifAlias table for the publish.
// Owned by pollOnce (never concurrent with itself). A device whose names were
// not read this cycle keeps its last aliases; a device that leaves the target
// set loses them.
type ifAliasRows map[string]map[string]string

// update folds one cycle into the rows and returns what to publish.
func (a ifAliasRows) update(targets []Target, results []deviceOutcome) map[string]map[string]string {
	in := make(map[string]bool, len(targets))
	for i, tg := range targets {
		in[tg.ID] = true
		r := results[i]
		if r.id == "" || !r.ifaliasRead {
			continue
		}
		if len(r.ifalias) == 0 {
			delete(a, tg.ID)
			continue
		}
		if _, ok := a[tg.ID]; !ok && len(a) >= maxIfAliasDevices {
			continue
		}
		a[tg.ID] = r.ifalias
	}
	for id := range a {
		if !in[id] {
			delete(a, id)
		}
	}
	out := make(map[string]map[string]string, len(a))
	for id, rows := range a {
		out[id] = rows
	}
	return out
}
