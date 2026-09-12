// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacRoutingSection — Administration → Ticket delivery → TAC routing.
//
// WHY IT SITS BESIDE THE CONNECTOR CONFIGURATION AND NOT INSIDE IT. The
// Configure form edits CREDENTIALS: write-only, sealed, never echoed back, and
// rotated on a security team's clock. This edits CHOICES and ENTITLEMENT
// IDENTIFIERS: which connector carries which vendor's cases, which capture runs
// on which platform, the support contract number, the CCO-ID, and the named
// human a vendor calls back. None of it is a secret, all of it is echoed back
// here, and a contract is renewed once a year. Two records, two stores, one
// isolation model (internal/ticketing/caseconn_routing.go).
//
// WHAT IT BUYS. Filled in once, per tenant, the one-click escalation arrives at
// its confirmation screen ALREADY COMPLETE — the serial and model from the
// device record, the contract and account id from here, the contact from here,
// the connector from here. Everything the owner described as "one or two
// clicks" depends on this page having been visited once.
//
// HONESTY. An unconfigured connector is still OFFERED as a route, labelled as
// having no credentials: a tenant route naming one is honoured by the server
// and then refused BY NAME on the confirmation screen, and hiding the choice
// would make that rule unreachable. An expired contract WARNS on the
// escalation; it never refuses, because a vendor may still take the case and
// Correlix does not get to decide that.
//
// §3a: the body never carries a tenant — the server stamps the owner from the
// token. §15 LLM02: every vendor-authored string here is escaped React text.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type TacCommandCapture,
  type TacConnectorInfo,
  type TacRoutingConfig,
  type TacRoutingDialect,
  type TacVendorContract,
} from "../../services/api";
import AskIris from "../../components/AskIris";
import { operatorError } from "../../lib/errors";
import {
  MAX_ROUTING_FIELD,
  MAX_SERIAL,
  ROUTING_EMPTY,
  ROUTING_READ_FAILED,
  ROUTING_SAVED,
  ROUTING_SAVE_FAILED,
  accountLabel,
  buildRoutingSave,
  captureFor,
  connectorChoiceLabel,
  connectorsForVendor,
  contractFor,
  emptyRouting,
  overrideRows,
  routeFor,
  routingVendors,
  validateRouting,
  vendorDisplay,
} from "./tacRoutingModel";

/** "Correlix decides" — the default every unset row carries. */
const AUTO_ROUTE = "Correlix chooses the path";
/** The Correlix default capture, which is what runs when nothing is preferred. */
const AUTO_CAPTURE = "Correlix default";

export default function TacRoutingSection() {
  const [routing, setRouting] = useState<TacRoutingConfig | null>(null);
  const [connectors, setConnectors] = useState<TacConnectorInfo[]>([]);
  const [dialects, setDialects] = useState<TacRoutingDialect[]>([]);
  const [captures, setCaptures] = useState<TacCommandCapture[]>([]);
  const [configured, setConfigured] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState<"" | "save" | "remove">("");
  const [newSerial, setNewSerial] = useState("");
  const [newSerialVendor, setNewSerialVendor] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await api.tacRouting();
      setRouting(r.routing ?? emptyRouting());
      setConnectors(r.connectors ?? []);
      setDialects(r.dialects ?? []);
      setConfigured(Boolean(r.configured));
      setErr(null);
    } catch (e) {
      setRouting(null);
      setErr(operatorError(e, ROUTING_READ_FAILED));
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  // This tenant's own saved captures, so a preferred capture is CHOSEN from
  // what exists rather than typed as an id. Best-effort: a tenant with none
  // still edits its routes and its contracts.
  useEffect(() => {
    let alive = true;
    api.tacCaptures()
      .then((r) => { if (alive) setCaptures(r.captures ?? []); })
      .catch(() => { if (alive) setCaptures([]); });
    return () => { alive = false; };
  }, []);

  const vendors = useMemo(() => routingVendors(connectors), [connectors]);

  const patch = useCallback((next: Partial<TacRoutingConfig>) => {
    setRouting((r) => (r ? { ...r, ...next } : r));
    setNote(null);
  }, []);

  const setContract = useCallback((vendor: string, field: keyof TacVendorContract, value: string) => {
    setRouting((r) => {
      if (!r) return r;
      const byVendor = { ...(r.contract_by_vendor ?? {}) };
      byVendor[vendor] = { ...(byVendor[vendor] ?? { vendor }), vendor, [field]: value };
      return { ...r, contract_by_vendor: byVendor };
    });
    setNote(null);
  }, []);

  const setOverride = useCallback((serial: string, field: keyof TacVendorContract, value: string) => {
    setRouting((r) => {
      if (!r) return r;
      const bySerial = { ...(r.contract_by_serial ?? {}) };
      bySerial[serial] = { ...(bySerial[serial] ?? { vendor: "" }), [field]: value } as TacVendorContract;
      return { ...r, contract_by_serial: bySerial };
    });
    setNote(null);
  }, []);

  const dropOverride = useCallback((serial: string) => {
    setRouting((r) => {
      if (!r) return r;
      const bySerial = { ...(r.contract_by_serial ?? {}) };
      delete bySerial[serial];
      return { ...r, contract_by_serial: bySerial };
    });
    setNote(null);
  }, []);

  const addOverride = useCallback(() => {
    const serial = newSerial.trim().toUpperCase();
    if (!serial) return;
    setRouting((r) => {
      if (!r) return r;
      const bySerial = { ...(r.contract_by_serial ?? {}) };
      if (!bySerial[serial]) bySerial[serial] = { vendor: newSerialVendor };
      return { ...r, contract_by_serial: bySerial };
    });
    setNewSerial("");
    setNote(null);
  }, [newSerial, newSerialVendor]);

  const save = useCallback(async () => {
    if (!routing) return;
    const body = buildRoutingSave(routing);
    const bad = validateRouting(body);
    if (bad) { setErr(bad); return; }
    setBusy("save");
    setNote(null);
    try {
      const r = await api.tacRoutingSave(body);
      setRouting(r.routing ?? emptyRouting());
      setConfigured(Boolean(r.configured));
      setErr(null);
      setNote(ROUTING_SAVED);
    } catch (e) {
      setErr(operatorError(e, ROUTING_SAVE_FAILED));
    } finally {
      setBusy("");
    }
  }, [routing]);

  const remove = useCallback(async () => {
    setBusy("remove");
    setNote(null);
    try {
      await api.tacRoutingDelete();
      setRouting(emptyRouting());
      setConfigured(false);
      setErr(null);
      setNote(ROUTING_SAVED);
    } catch (e) {
      setErr(operatorError(e, ROUTING_SAVE_FAILED));
    } finally {
      setBusy("");
    }
  }, []);

  if (!routing && err) {
    return (
      <section className="tdr" data-testid="tac-routing">
        <h3 style={{ marginBottom: "var(--sp-1)" }}>TAC routing</h3>
        <p role="alert" className="adm-line" style={{ color: "var(--bad)" }}>{err}</p>
      </section>
    );
  }
  if (!routing) {
    return (
      <section className="tdr" data-testid="tac-routing">
        <h3 style={{ marginBottom: "var(--sp-1)" }}>TAC routing</h3>
        <p className="adm-line" role="status">Reading your TAC routing…</p>
      </section>
    );
  }

  const overrides = overrideRows(routing);

  return (
    <section className="tdr" data-testid="tac-routing">
      <h3 style={{ marginBottom: "var(--sp-1)" }}>TAC routing</h3>
      <p className="adm-line">
        Who a vendor calls back, and where each vendor&apos;s cases go.
        <AskIris topic="tac.case-connector" label="TAC routing" />
      </p>
      {!configured && <p className="adm-line">{ROUTING_EMPTY}</p>}

      <h4 className="tdr-h">TAC contact</h4>
      <div className="tdc-form" data-testid="tac-routing-contact">
        {([
          ["name", "Name"], ["email", "Email"], ["phone", "Phone"],
        ] as [keyof TacRoutingConfig["contact"], string][]).map(([key, label]) => (
          <div className="tdc-field" key={key}>
            <label htmlFor={`tacr-contact-${key}`}>{label}</label>
            <input
              id={`tacr-contact-${key}`}
              type="text"
              maxLength={MAX_ROUTING_FIELD}
              value={routing.contact[key] ?? ""}
              onChange={(e) => patch({ contact: { ...routing.contact, [key]: e.target.value } })}
            />
          </div>
        ))}
      </div>

      <h4 className="tdr-h">Case routes</h4>
      {vendors.length === 0 ? (
        <p className="adm-line">No vendor path on this deployment.</p>
      ) : (
        <div className="tdc-form" data-testid="tac-routing-routes">
          {vendors.map((v) => (
            <div className="tdc-field" key={`route-${v}`}>
              <label htmlFor={`tacr-route-${v}`}>{vendorDisplay(v)}</label>
              <select
                id={`tacr-route-${v}`}
                value={routeFor(routing, v)}
                onChange={(e) => patch({
                  route_by_vendor: { ...(routing.route_by_vendor ?? {}), [v]: e.target.value },
                })}
              >
                <option value="">{AUTO_ROUTE}</option>
                {connectorsForVendor(connectors, v).map((c) => (
                  <option key={c.id} value={c.id}>{connectorChoiceLabel(c)}</option>
                ))}
              </select>
            </div>
          ))}
        </div>
      )}

      <h4 className="tdr-h">Preferred captures</h4>
      {dialects.length === 0 ? (
        <p className="adm-line">No platform carries a capture yet.</p>
      ) : (
        <div className="tdc-form" data-testid="tac-routing-captures">
          {dialects.map((d) => {
            const own = captures.filter((c) => c.dialect === d.dialect);
            return (
              <div className="tdc-field" key={`cap-${d.dialect}`}>
                <label htmlFor={`tacr-cap-${d.dialect}`}>{d.display || d.dialect}</label>
                <select
                  id={`tacr-cap-${d.dialect}`}
                  value={captureFor(routing, d.dialect)}
                  onChange={(e) => patch({
                    capture_by_dialect: { ...(routing.capture_by_dialect ?? {}), [d.dialect]: e.target.value },
                  })}
                >
                  <option value="">{AUTO_CAPTURE}</option>
                  {own.map((c) => (
                    <option key={c.id} value={c.id}>{c.name}</option>
                  ))}
                </select>
              </div>
            );
          })}
        </div>
      )}

      <h4 className="tdr-h">Vendor contracts</h4>
      <p className="adm-line">
        What a vendor checks before it opens anything.
        <AskIris topic="tac.case-connector" label="Vendor contracts" />
      </p>
      {vendors.map((v) => {
        const c = contractFor(routing, v);
        return (
          <div className="tdc-form" key={`ct-${v}`} data-testid={`tac-contract-${v}`}>
            <div className="tdc-field"><b>{vendorDisplay(v)}</b></div>
            {([
              ["contract_id", "Contract or service agreement"],
              ["account_id", accountLabel(v)],
              ["site_id", "Site id"],
              ["support_level", "Support level"],
            ] as [keyof TacVendorContract, string][]).map(([field, label]) => (
              <div className="tdc-field" key={`${v}-${field}`}>
                <label htmlFor={`tacr-${v}-${field}`}>{label}</label>
                <input
                  id={`tacr-${v}-${field}`}
                  type="text"
                  maxLength={MAX_ROUTING_FIELD}
                  value={c[field] ?? ""}
                  onChange={(e) => setContract(v, field, e.target.value)}
                />
              </div>
            ))}
            <div className="tdc-field">
              <label htmlFor={`tacr-${v}-expires_on`}>Covered until</label>
              <input
                id={`tacr-${v}-expires_on`}
                type="text"
                inputMode="numeric"
                placeholder="2027-03-31"
                maxLength={10}
                value={c.expires_on ?? ""}
                onChange={(e) => setContract(v, "expires_on", e.target.value)}
              />
            </div>
          </div>
        );
      })}

      <h4 className="tdr-h">Device overrides</h4>
      <p className="adm-line">
        A serial the vendor entitles on its own contract.
        <AskIris topic="tac.case-connector" label="Device overrides" />
      </p>
      <div className="tdc-form" data-testid="tac-routing-overrides">
        {overrides.map(({ serial, contract }) => (
          <div className="tdc-field" key={`ov-${serial}`} data-testid={`tac-override-${serial}`}>
            <label htmlFor={`tacr-ov-${serial}`}>{serial}</label>
            <select
              id={`tacr-ov-${serial}`}
              value={(contract.vendor ?? "").toLowerCase()}
              onChange={(e) => setOverride(serial, "vendor", e.target.value)}
            >
              <option value="">Vendor</option>
              {vendors.map((v) => <option key={v} value={v}>{vendorDisplay(v)}</option>)}
            </select>
            <input
              type="text"
              aria-label={`Contract for ${serial}`}
              maxLength={MAX_ROUTING_FIELD}
              value={contract.contract_id ?? ""}
              onChange={(e) => setOverride(serial, "contract_id", e.target.value)}
            />
            <input
              type="text"
              aria-label={`${accountLabel(contract.vendor ?? "")} for ${serial}`}
              maxLength={MAX_ROUTING_FIELD}
              value={contract.account_id ?? ""}
              onChange={(e) => setOverride(serial, "account_id", e.target.value)}
            />
            <input
              type="text"
              aria-label={`Covered until, for ${serial}`}
              placeholder="2027-03-31"
              maxLength={10}
              value={contract.expires_on ?? ""}
              onChange={(e) => setOverride(serial, "expires_on", e.target.value)}
            />
            <button type="button" className="btn" onClick={() => dropOverride(serial)}>Remove</button>
          </div>
        ))}
        <div className="tdc-field">
          <label htmlFor="tacr-new-serial">Serial</label>
          <input
            id="tacr-new-serial"
            type="text"
            maxLength={MAX_SERIAL}
            value={newSerial}
            onChange={(e) => setNewSerial(e.target.value)}
          />
          <select
            aria-label="Vendor for the new override"
            value={newSerialVendor}
            onChange={(e) => setNewSerialVendor(e.target.value)}
          >
            <option value="">Vendor</option>
            {vendors.map((v) => <option key={v} value={v}>{vendorDisplay(v)}</option>)}
          </select>
          <button type="button" className="btn" onClick={addOverride} data-testid="tac-override-add">Add</button>
        </div>
      </div>

      <div className="tdc-form-actions">
        <button
          type="button"
          className="btn"
          disabled={busy !== ""}
          onClick={() => { void save(); }}
          data-testid="tac-routing-save"
        >
          {busy === "save" ? "Saving…" : "Save"}
        </button>
        <button
          type="button"
          className="btn"
          disabled={busy !== "" || !configured}
          onClick={() => { void remove(); }}
          data-testid="tac-routing-remove"
        >
          {busy === "remove" ? "Removing…" : "Remove"}
        </button>
        {note && <span className="adm-line" role="status" data-testid="tac-routing-note">{note}</span>}
      </div>
      {err && <p className="adm-line" role="alert" style={{ color: "var(--bad)" }} data-testid="tac-routing-error">{err}</p>}
    </section>
  );
}
