// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// WhoIsTalking — the second tab of Explore → Flows: conversations,
// applications, services, services and ports, protocols — and countries and
// networks only when their datasets are loaded — under ONE chip filter bar.
//
// Devices and interfaces are picked by NAME (inventory names; interface names
// from the device's own IF-MIB via the interface top-N), never typed as an
// address or an ifIndex. Every chip except Application narrows the flow
// queries on the server; Application narrows the application and service
// lists, which take only the window.

import { useMemo, useState } from "react";
import { api, type Device } from "../../services/api";
import { buildDeviceNames } from "../../lib/deviceNames";
import { Segmented } from "../../components/ui";
import { fetchCoverage } from "../flowEmpty";
import type { TopNRow } from "../flowNames";
import {
  checkAddress, checkPort, deviceOptions, filterChips, FLOW_SOURCES, interfaceOptions, protoNumber,
  serverFilterKeys, toFlowFilters, withoutChip, type IfDir, type TalkFilters,
} from "./flowsModel";
import {
  ApplicationsSection, ConversationsSection, CountriesSection, NetworksSection, PortsSection, ProtocolsSection,
  ServicesSection, TopNPanel, type FlowQuery,
} from "./talkingSections";
import { useTicked } from "./useTicked";

export type TalkView = "conversations" | "apps" | "services" | "ports" | "protocols" | "countries" | "networks";
type AddKind = "device" | "if" | "addr" | "port" | "proto" | "app";

const ADD_LABEL: Record<AddKind, string> = {
  device: "Device",
  if: "Interface",
  addr: "Address or network",
  port: "Port",
  proto: "Protocol",
  app: "Application",
};

export default function WhoIsTalking({ since, filters, onFilters, includePlatform }: {
  since: number;
  filters: TalkFilters;
  onFilters: (f: TalkFilters) => void;
  includePlatform: boolean;
}) {
  const [view, setView] = useState<TalkView>("conversations");
  const flowFilters = toFlowFilters(filters, includePlatform);
  const fkey = JSON.stringify(flowFilters);
  const q: FlowQuery = { since, ftype: filters.type ?? "", filters: flowFilters, fkey, direction: filters.direction ?? "" };

  // Pickers: inventory devices + exporters that send flows; the chosen device's interfaces.
  const devices = useTicked<Device[]>(() => api.devices(), []);
  const names = useMemo(() => buildDeviceNames(devices.data ?? []), [devices.data]);
  const exporters = useTicked(() => api.flowsTopN("device", since, 200), [since]);
  const devOpts = useMemo(
    () => deviceOptions(devices.data ?? [], ((exporters.data?.data as TopNRow[]) ?? []).map((r) => String(r.k)), names),
    [devices.data, exporters.data, names],
  );
  const ifRows = useTicked(
    () => Promise.all([
      api.flowsTopN("in_if", since, 200, "", { device: filters.device }),
      api.flowsTopN("out_if", since, 200, "", { device: filters.device }),
    ]),
    [filters.device, since],
    !!filters.device,
  );
  const ifOpts = useMemo(
    () => (filters.device && ifRows.data ? interfaceOptions((ifRows.data[0]?.data as TopNRow[]) ?? [], (ifRows.data[1]?.data as TopNRow[]) ?? [], filters.device) : []),
    [ifRows.data, filters.device],
  );

  // Countries and networks appear only once their datasets are loaded.
  const geo = useTicked(() => api.flowsGeo("src", since, "", undefined), [since]);
  const cov = useTicked(() => fetchCoverage(since, "", undefined), [since]);
  const geoOn = !!geo.data && geo.data.geo_enabled !== false;
  const asOn = !!cov.data && (cov.data.flows_with_as > 0 || cov.data.asn_dataset_loaded);

  const views: { value: TalkView; label: string }[] = [
    { value: "conversations", label: "Conversations" },
    { value: "apps", label: "Applications" },
    { value: "services", label: "Services" },
    { value: "ports", label: "Services and ports" },
    { value: "protocols", label: "Protocols" },
    ...(geoOn ? [{ value: "countries" as const, label: "Countries" }] : []),
    ...(asOn ? [{ value: "networks" as const, label: "Networks" }] : []),
  ];
  const active = views.some((v) => v.value === view) ? view : "conversations";
  const keys = serverFilterKeys(filters);
  const chipNames = {
    device: devOpts.find((o) => o.value === filters.device)?.label,
    iface: ifOpts.find((o) => o.value === filters.if)?.label,
  };

  return (
    <>
      <FilterBar filters={filters} onFilters={onFilters} devOpts={devOpts} ifOpts={ifOpts} chipNames={chipNames} />
      <Segmented<TalkView> value={active} ariaLabel="Flows view" options={views} onChange={setView} />
      {active === "conversations" && (
        <>
          <ConversationsSection q={q} />
          <div className="flows-grid">
            <TopNPanel title="Busiest sources" by="src_addr" q={q} keyHeader="Source" />
            <TopNPanel title="Busiest destinations" by="dst_addr" q={q} keyHeader="Destination" />
          </div>
        </>
      )}
      {active === "apps" && <ApplicationsSection q={q} filterKeys={keys} appFilter={filters.app} onDrill={() => setView("conversations")} />}
      {active === "services" && <ServicesSection q={q} filterKeys={keys} appFilter={filters.app} onDrill={() => setView("conversations")} />}
      {active === "ports" && <PortsSection q={q} />}
      {active === "protocols" && <ProtocolsSection q={q} />}
      {active === "countries" && <CountriesSection q={q} />}
      {active === "networks" && <NetworksSection q={q} />}
    </>
  );
}

// ── the chip bar ─────────────────────────────────────────────────────────────

function FilterBar({ filters, onFilters, devOpts, ifOpts, chipNames }: {
  filters: TalkFilters;
  onFilters: (f: TalkFilters) => void;
  devOpts: { value: string; label: string }[];
  ifOpts: { value: string; label: string }[];
  chipNames: { device?: string; iface?: string };
}) {
  const [kind, setKind] = useState<AddKind>("device");
  const [value, setValue] = useState("");
  const [ifDir, setIfDir] = useState<IfDir>("either");
  const [problem, setProblem] = useState<string | null>(null);
  const chips = filterChips(filters, chipNames);
  const kinds = (Object.keys(ADD_LABEL) as AddKind[]).filter((k) => k !== "if" || !!filters.device);

  const add = () => {
    const v = value.trim();
    let next: TalkFilters | null = null;
    let why: string | null = null;
    switch (kind) {
      case "device":
        if (!v) why = "Choose a device.";
        else next = { ...filters, device: v, if: undefined, ifDir: undefined };
        break;
      case "if":
        if (!v) why = "Choose an interface.";
        else next = { ...filters, if: v, ifDir };
        break;
      case "addr":
        why = checkAddress(v);
        if (!why) next = { ...filters, addr: v };
        break;
      case "port":
        why = checkPort(v);
        if (!why) next = { ...filters, port: String(Number(v)) };
        break;
      case "proto": {
        const n = protoNumber(v);
        if (n === null) why = "Use a protocol name like TCP or a number from 0 to 255.";
        else next = { ...filters, proto: n };
        break;
      }
      case "app":
        if (!v) why = "Enter part of an application name.";
        else next = { ...filters, app: v };
        break;
    }
    setProblem(why);
    if (next) {
      onFilters(next);
      setValue("");
    }
  };

  return (
    <div className="card tr-filterbar" role="search" aria-label="Filter flows">
      <div className="tr-add">
        <select aria-label="Filter by" value={kind} onChange={(e) => { setKind(e.target.value as AddKind); setValue(""); setProblem(null); }}>
          {kinds.map((k) => <option key={k} value={k}>{ADD_LABEL[k]}</option>)}
        </select>
        {kind === "device" && (
          <select aria-label="Device" value={value} onChange={(e) => setValue(e.target.value)}>
            <option value="">Choose a device…</option>
            {devOpts.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        )}
        {kind === "if" && (
          <>
            <select aria-label="Interface" value={value} onChange={(e) => setValue(e.target.value)}>
              <option value="">Choose an interface…</option>
              {ifOpts.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
            <select aria-label="Direction on the interface" value={ifDir} onChange={(e) => setIfDir(e.target.value as IfDir)}>
              <option value="either">Entering or leaving</option>
              <option value="in">Entering</option>
              <option value="out">Leaving</option>
            </select>
          </>
        )}
        {(kind === "addr" || kind === "port" || kind === "proto" || kind === "app") && (
          <input
            aria-label={ADD_LABEL[kind]}
            value={value}
            placeholder={kind === "addr" ? "10.1.2.3 or 10.1.0.0/16" : kind === "port" ? "443" : kind === "proto" ? "TCP" : "Application name"}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") add(); }}
          />
        )}
        <button className="btn-primary" onClick={add}>Add</button>
        <select aria-label="Flow source" value={filters.type ?? ""} onChange={(e) => onFilters({ ...filters, type: e.target.value || undefined })}>
          {FLOW_SOURCES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>
        <Segmented<"" | "bi">
          value={filters.direction ?? ""}
          ariaLabel="Direction"
          options={[{ value: "", label: "Each direction" }, { value: "bi", label: "Both as one" }]}
          onChange={(d) => onFilters({ ...filters, direction: d || undefined })}
        />
      </div>
      {problem && <p className="tr-error tr-problem" role="alert">{problem}</p>}
      {chips.length > 0 && (
        <div className="tr-chips" aria-label="Active filters">
          {chips.map((c) => (
            <span key={c.key} className="tr-chip">
              {c.label}
              <button aria-label={`Remove ${c.label}`} onClick={() => onFilters(withoutChip(filters, c.key))}>×</button>
            </span>
          ))}
          <button className="btn-ghost" onClick={() => onFilters({})}>Clear all</button>
        </div>
      )}
    </div>
  );
}
