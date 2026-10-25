// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// controller_instance.go — which CONTROLLER relayed an event, as opposed to
// which integration polled it.
//
// The correlation engine needs this to tell observations apart: two edges'
// BFD sessions relayed by one vManage are two observations through ONE
// management plane, and two integrations configured against the same vManage
// are still that one plane. The integration id cannot say either — it changes
// when an integration is re-created, and two integrations of one controller
// have two ids. Today the value is context only (attrs); the verdict's
// independence rule (NMS-first plan T2) is what will read it.
//
// Basis "host": the controller's normalized address. An IP and an FQDN for the
// same controller, or two nodes of one cluster, still come out as different
// instances — the unsafe direction for a witness count, so T2 must treat
// basis "host" conservatively. A controller-reported cluster id ("reported")
// replaces it when a connector learns one.

// ControllerInstanceID returns the instance id and its basis for an
// integration. An unparseable base URL, or one that names no host, is an
// error: the caller reports it rather than stamping nothing silently.
func ControllerInstanceID(spec ConnectorSpec, baseURL string) (id, basis string, err error) {
	host, err := normalizedControllerHost(baseURL)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(spec.Maker + "|" + spec.Vendor + "|" + host))
	return "ci-" + hex.EncodeToString(sum[:8]), "host", nil
}

var errNoControllerHost = errors.New("controller base URL names no host")

func normalizedControllerHost(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", fmt.Errorf("controller base URL: %w", err)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", errNoControllerHost
	}
	port := u.Port()
	switch {
	case port == "", port == "443" && strings.EqualFold(u.Scheme, "https"), port == "80" && strings.EqualFold(u.Scheme, "http"):
		return host, nil
	}
	return net.JoinHostPort(host, port), nil
}

// stampControllerInstance sets ControllerInstance (and its basis hint) on every
// event of one integration's cycle. Hints are copied, never mutated in place:
// a transformer may share one map between events. A base URL that yields no
// instance is returned to the caller to report; the events still flow.
func stampControllerInstance(events []ControllerEvent, spec ConnectorSpec, ic Integration) error {
	if len(events) == 0 {
		return nil
	}
	id, basis, err := ControllerInstanceID(spec, ic.BaseURL)
	if err != nil {
		return err
	}
	for i := range events {
		events[i].ControllerInstance = id
		hints := make(map[string]string, len(events[i].CorrelationHints)+1)
		for k, v := range events[i].CorrelationHints {
			hints[k] = v
		}
		hints["controller_instance_basis"] = basis
		events[i].CorrelationHints = hints
	}
	return nil
}
