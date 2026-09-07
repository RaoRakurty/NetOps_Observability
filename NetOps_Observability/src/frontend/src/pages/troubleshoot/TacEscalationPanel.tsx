// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacEscalationPanel — the TAC escalation flow, one panel, incident-first.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md for the engine,
// docs/design/TAC_CAPTURES_2026-09-06.md for what the customer SEES — the owner
// decision that replaced the plan → review → collect presentation:
//
//   "Process of extracting the commands and building default template even
//    before case opening is your job. This process should be not visible to
//    customer … you can collapse all the commands … Review the commands not
//    needed, instead give an option to upload their own list … When it's
//    collecting it's good to see the status. Instead of showing all the command
//    outputs, just display the ones that didn't work … Give an option to look
//    what is happening behind the scene."
//
// So the visible escalation is four things:
//
//   1. a device                — where the outputs come from
//   2. CAPTURES                — named command lists: Correlix's own (derived
//                                from the plan, silently), this tenant's saved
//                                sets, and one the customer uploads. A row is a
//                                name, a count and a coloured status; the
//                                commands are hidden until the chevron is used.
//   3. the bundle              — the redacted zip the SERVER builds
//   4. the case                — a pre-filled form a PERSON submits
//
// and ONE control, "What Correlix is doing", that reveals the class it chose,
// the commands with their sources and verification state, and the collection
// log. Nothing was deleted from the product; what changed is what a person is
// made to read before they can escalate.
//
// HONESTY (the reason the feature exists). Nothing here is filled in to look
// finished. A capture that never ran reads "Queued" rather than borrowing
// another row's verdict. A partial collection lists ONLY the commands that
// failed, each with its plain reason; the successful output is in the bundle and
// is never rendered. A 503 on collect renders the server's own collect_note and
// leaves the paste path open. An upload is refused WHOLE, by line number and by
// the rule that refused it — Correlix never runs part of a list.
//
// SECURITY (§3 zero trust / §15 untrusted output). Command output, uploaded
// command text, the problem statement, connector notes and case text are all
// remote- or customer-authored. Every one of them is rendered as an escaped
// React text node — there is no innerHTML and no dangerouslySetInnerHTML in this
// file. The upload is parsed and policy-checked SERVER-side; the client refuses
// nothing on its own authority. The download name is built from a closed
// character set, so a remote string cannot steer a file path.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  type Device,
  type TacCaptureRefusal,
  type TacCaptureStatus,
  type TacCaseForm,
  type TacCaseResult,
  type TacClassifyResponse,
  type TacCommandCapture,
  type TacCommandStatus,
  type TacConnectorInfo,
  type TacCollectRequest,
  type TacPlan,
  type TacState,
  type TacStateResponse,
  type TacStep,
  type TacTarget,
} from "../../services/api";
import {
  BEHIND_LABEL,
  BUNDLE_FAILED,
  BUNDLE_PROFILES,
  CANCEL_FAILED,
  CAPTURES_FAILED,
  CAPTURES_NEED_DEVICE,
  CAPTURES_NONE,
  CAPTURE_SAVE_FAILED,
  CAPTURE_SOURCE_LABEL,
  CAPTURE_STATUS_LABEL,
  CASE_FORM_FAILED,
  CASE_HUMAN_APPROVED,
  CASE_SUBMIT_FAILED,
  CLASSIFY_FAILED,
  CONNECTOR_CHIP,
  DEVICES_FAILED,
  MAX_PASTE_CHARS,
  NOT_ESCALATED_NOTE,
  NO_AUTHORED_PLAN_NOTE,
  NO_BUNDLE_YET,
  NO_CAPTURE_YET,
  NO_CASE_CONNECTOR,
  PASTE_INVITE,
  PLAN_FAILED,
  PLAN_LEGEND,
  REDACTION_SHORT,
  ROW_RENDER_CAP,
  SECTION_ORDER,
  STATE_READ_FAILED,
  STATUS_CHIP,
  TEMPLATE_NEEDS_NAME,
  TICKET_DELIVERY_LABEL,
  TICKET_DELIVERY_ROUTE,
  UPLOAD_FAILED,
  UPLOAD_FORMATS_LINE,
  boundSteps,
  buildCaptureWrite,
  buildPlanRequest,
  bundleFileName,
  cappedNote,
  captureBarPercent,
  captureRowStatus,
  captureRows,
  ceilingSuffix,
  classificationNote,
  collectErrorMessage,
  commandCountLine,
  connectorCapabilityLine,
  connectorState,
  connectorStatusNote,
  connectorTopic,
  dialectVendor,
  evidenceLine,
  failedCommandLine,
  failedCommands,
  hasCapability,
  humanBytes,
  isCollecting,
  isMissingField,
  missingOutputs,
  missingOutputsLine,
  newestBundleBytes,
  parseCaptureRefusals,
  pasteOffered,
  pasteOptionLabel,
  phaseLabel,
  planHeadline,
  planVersionTitle,
  reasonLine,
  refusalLine,
  selectedCapture,
  showAllConnectorsLabel,
  splitConnectors,
  stepReference,
  stepStatus,
  stepTooltip,
  tacError,
  topologyLine,
  unavailableLine,
  unboundReason,
  verifiedLabel,
} from "./tacModel";
import AskIris from "../../components/AskIris";

/** The editable half of the case form — everything the vendor wants from a human. */
type CaseFields = {
  title: string; severity: string; product: string; serial_number: string;
  contract_id: string; contact_name: string; contact_email: string;
};

const EMPTY_FIELDS: CaseFields = {
  title: "", severity: "", product: "", serial_number: "",
  contract_id: "", contact_name: "", contact_email: "",
};

const CASE_FIELD_LABEL: { key: keyof CaseFields; label: string }[] = [
  { key: "title", label: "Title" },
  { key: "severity", label: "Severity" },
  { key: "product", label: "Product" },
  { key: "serial_number", label: "Serial number" },
  { key: "contract_id", label: "Contract" },
  { key: "contact_name", label: "Contact name" },
  { key: "contact_email", label: "Contact email" },
];

/** The formats the file picker offers, from the parser's own list. */
const UPLOAD_ACCEPT = ".txt,.text,.list,.csv,.json,.yaml,.yml,.docx";

export default function TacEscalationPanel({ incidentId }: { incidentId: string }) {
  const [info, setInfo] = useState<TacStateResponse | null>(null);
  const [infoErr, setInfoErr] = useState("");
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesErr, setDevicesErr] = useState("");

  const [classify, setClassify] = useState<TacClassifyResponse | null>(null);
  const [classErr, setClassErr] = useState("");
  const [classifying, setClassifying] = useState(false);
  const [classOverride, setClassOverride] = useState("");

  const [deviceId, setDeviceId] = useState("");
  const [target, setTarget] = useState<TacTarget>({});
  const [includeOptional, setIncludeOptional] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [planErr, setPlanErr] = useState("");

  // ── captures (docs/design/TAC_CAPTURES_2026-09-06.md) ─────────────────────
  // `saved` is this tenant's own sets; `uploaded` is a file in hand for THIS
  // escalation (never stored until it is saved); `selectedId` is the one that
  // will run; `expanded` is which rows have had their chevron used — nothing is
  // expanded by default, which is the whole point of the row.
  const [saved, setSaved] = useState<TacCommandCapture[]>([]);
  const [savedErr, setSavedErr] = useState("");
  const [uploaded, setUploaded] = useState<TacCommandCapture | null>(null);
  const [uploadErr, setUploadErr] = useState("");
  const [refusals, setRefusals] = useState<TacCaptureRefusal[]>([]);
  const [uploading, setUploading] = useState(false);
  const [selectedId, setSelectedId] = useState("");
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [saveName, setSaveName] = useState("");
  const [saveErr, setSaveErr] = useState("");
  const [saveNote, setSaveNote] = useState("");
  const [saving, setSaving] = useState(false);

  // The one disclosure. Its body is MOUNTED only while open, so what the step
  // does not show is not merely hidden by CSS — it is not in the document.
  const [behindOpen, setBehindOpen] = useState(false);

  const [collectBusy, setCollectBusy] = useState(false);
  const [collectErr, setCollectErr] = useState("");
  // The paste path is ONE control (owner, 2026-09-06): which output is missing,
  // the text, and a button. Not a textarea per intent in the whole class.
  const [pasteIntent, setPasteIntent] = useState("");
  const [pasteText, setPasteText] = useState("");

  const [bundleErr, setBundleErr] = useState("");
  const [bundleNote, setBundleNote] = useState("");
  const [bundleProfile, setBundleProfile] = useState("full");

  const [caseConnector, setCaseConnector] = useState<TacConnectorInfo | null>(null);
  const [caseForm, setCaseForm] = useState<TacCaseForm | null>(null);
  const [caseFields, setCaseFields] = useState<CaseFields>(EMPTY_FIELDS);
  const [caseErr, setCaseErr] = useState("");
  const [caseNote, setCaseNote] = useState("");
  const [caseResult, setCaseResult] = useState<TacCaseResult | null>(null);
  const [caseBusy, setCaseBusy] = useState(false);

  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const state: TacState | null = info?.state ?? null;
  const plan: TacPlan | undefined = state?.plan;
  const capture = state?.capture;
  const progress = state?.progress;
  const classification = classify?.classification ?? state?.classification;

  const readState = useCallback(async () => {
    try {
      const r = await api.tacState(incidentId);
      if (alive.current) { setInfo(r); setInfoErr(""); }
    } catch (e) {
      if (alive.current) setInfoErr(tacError(e, STATE_READ_FAILED));
    }
  }, [incidentId]);

  // The escalation's state, and the caller's own inventory for the device picker.
  useEffect(() => {
    setInfo(null); setInfoErr(""); setClassify(null); setClassErr("");
    setDeviceId(""); setPlanErr(""); setCollectErr(""); setPasteIntent(""); setPasteText("");
    setSaved([]); setSavedErr(""); setUploaded(null); setUploadErr(""); setRefusals([]);
    setSelectedId(""); setExpanded({}); setSaveName(""); setSaveErr(""); setSaveNote("");
    setCaseForm(null); setCaseConnector(null); setCaseResult(null); setCaseErr("");
    void readState();
  }, [incidentId, readState]);

  useEffect(() => {
    api.devices()
      .then((rows) => { if (alive.current) { setDevices(Array.isArray(rows) ? rows : []); setDevicesErr(""); } })
      .catch((e: unknown) => { if (alive.current) { setDevices([]); setDevicesErr(tacError(e, DEVICES_FAILED)); } });
  }, []);

  // Seed the device from the incident's own affected list, once.
  useEffect(() => {
    if (deviceId === "" && (info?.devices?.length ?? 0) > 0) setDeviceId(info!.devices[0]);
  }, [info, deviceId]);

  // LIVE collection: re-read the escalation every 2 s while the server says a
  // job is running, and stop the moment it is not. The interval is cleared on
  // unmount and on every status change — a closed panel reads nothing.
  const running = isCollecting(state);
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => { void readState(); }, 2000);
    return () => clearInterval(id);
  }, [running, readState]);

  // ── actions ───────────────────────────────────────────────────────────────

  const runClassify = async () => {
    setClassErr(""); setClassifying(true);
    try {
      const r = await api.tacClassify(incidentId);
      if (!alive.current) return;
      setClassify(r);
      setClassOverride(r.classification?.class_id ?? "");
      await readState();
    } catch (e) {
      if (alive.current) setClassErr(tacError(e, CLASSIFY_FAILED));
    } finally {
      if (alive.current) setClassifying(false);
    }
  };

  const runPlan = useCallback(async () => {
    if (!deviceId.trim()) return;
    setPlanErr(""); setPlanning(true);
    try {
      const classId = classOverride || classification?.class_id || "";
      await api.tacPlan(incidentId, buildPlanRequest(deviceId, classId, includeOptional, target));
      if (alive.current) await readState();
    } catch (e) {
      if (alive.current) setPlanErr(tacError(e, PLAN_FAILED));
    } finally {
      if (alive.current) setPlanning(false);
    }
    // `target` is deliberately not a dependency: it is applied when the operator
    // presses Rebuild, not on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId, deviceId, classOverride, classification?.class_id, includeOptional, readState]);

  // THE EXTRACTION IS SILENT (owner, 2026-09-06). Once the class is known and a
  // device is chosen, the plan is built without anybody pressing anything: the
  // customer is never asked to review it, so asking them to trigger it would be
  // asking them to think about a step that is not theirs.
  const started = Boolean(classification);
  const autoKey = `${deviceId}|${classOverride || classification?.class_id || ""}|${includeOptional}`;
  const lastPlanned = useRef("");
  useEffect(() => {
    if (!started || !deviceId.trim() || lastPlanned.current === autoKey) return;
    lastPlanned.current = autoKey;
    void runPlan();
  }, [started, deviceId, autoKey, runPlan]);

  // This tenant's saved captures for THIS device's dialect. A set written for
  // another vendor is never offered: a list of EOS commands is meaningless at a
  // Junos router.
  const dialect = plan?.dialect ?? "";
  useEffect(() => {
    if (!dialect) { setSaved([]); return; }
    api.tacCaptures(dialect)
      .then((r) => { if (alive.current) { setSaved(r.captures ?? []); setSavedErr(""); } })
      .catch((e: unknown) => {
        if (alive.current) { setSaved([]); setSavedErr(tacError(e, CAPTURES_FAILED)); }
      });
  }, [dialect]);

  const rows = useMemo(
    () => captureRows(state?.default_capture, uploaded, saved),
    [state?.default_capture, uploaded, saved],
  );
  const selected = useMemo(() => selectedCapture(rows, selectedId), [rows, selectedId]);

  /** Upload one file. Everything that decides whether it may run happens on the
   *  server; this renders the answer, including the per-line refusal. */
  const onUpload = async (file: File | undefined) => {
    if (!file) return;
    setUploadErr(""); setRefusals([]); setUploading(true);
    try {
      const r = await api.tacCaptureUpload(file, dialect);
      if (!alive.current) return;
      setUploaded(r.capture);
      setSelectedId(r.capture.id);
      setSaveName(r.capture.name || "");
    } catch (e) {
      if (!alive.current) return;
      setUploaded(null);
      const refused = parseCaptureRefusals(e);
      setRefusals(refused);
      setUploadErr(refused.length > 0 ? "" : tacError(e, UPLOAD_FAILED));
    } finally {
      if (alive.current) setUploading(false);
    }
  };

  /** Save the uploaded capture as one of this tenant's own sets. */
  const saveCapture = async () => {
    if (!uploaded) return;
    setSaveErr(""); setSaveNote("");
    if (!saveName.trim()) { setSaveErr(TEMPLATE_NEEDS_NAME); return; }
    setSaving(true);
    try {
      const r = await api.tacCaptureSave(buildCaptureWrite(dialect, saveName, uploaded.commands));
      if (!alive.current) return;
      setSaveNote(`Saved “${r.capture.name}”.`);
      const list = await api.tacCaptures(dialect);
      if (alive.current) setSaved(list.captures ?? []);
    } catch (e) {
      if (alive.current) setSaveErr(tacError(e, CAPTURE_SAVE_FAILED));
    } finally {
      if (alive.current) setSaving(false);
    }
  };

  // What is still missing, and whether the paste path is offered at all. Only
  // the plan's BOUND steps can be pasted for: an unbound intent has no command
  // to run and is already counted by the plan's "not available" line.
  const missing = useMemo(() => missingOutputs(plan, state), [plan, state]);
  const boundTotal = useMemo(() => boundSteps(plan).length, [plan]);
  const showPaste = pasteOffered(Boolean(info?.can_collect), plan, state);

  // Keep the picker on a target that still exists: filing an output removes it
  // from the list, and a stale selection would silently file nothing.
  useEffect(() => {
    if (missing.length === 0) { setPasteIntent(""); return; }
    if (!missing.some((s) => s.intent === pasteIntent)) setPasteIntent(missing[0].intent);
  }, [missing, pasteIntent]);

  const runCollect = async () => {
    setCollectErr(""); setCollectBusy(true);
    try {
      const body: TacCollectRequest = {};
      // The command list travels ONLY when the operator chose something other
      // than Correlix's own capture — otherwise the server runs the plan it
      // already holds, and the bundle honestly records that nothing was edited.
      if (selected && selected.source !== "vendor-default") {
        body.steps = selected.commands.map((c) => ({ command: c.command }));
        if (selected.source === "template") body.template_id = selected.id;
      }
      await api.tacCollect(incidentId, body);
      if (alive.current) await readState();
    } catch (e) {
      if (alive.current) setCollectErr(collectErrorMessage(e, info?.collect_note ?? ""));
    } finally {
      if (alive.current) setCollectBusy(false);
    }
  };

  /** File ONE pasted output for the selected step. The capture's command list is
   *  deliberately NOT sent: pasting an output is not a request to run anything. */
  const addPastedOutput = async () => {
    const step = missing.find((s) => s.intent === pasteIntent);
    const text = pasteText.trim();
    if (!step || !text) return;
    setCollectErr(""); setCollectBusy(true);
    try {
      await api.tacCollect(incidentId, {
        outputs: [{ intent: step.intent, command: step.command ?? "", output: text.slice(0, MAX_PASTE_CHARS) }],
      });
      if (alive.current) { setPasteText(""); await readState(); }
    } catch (e) {
      if (alive.current) setCollectErr(collectErrorMessage(e, info?.collect_note ?? ""));
    } finally {
      if (alive.current) setCollectBusy(false);
    }
  };

  const runCancel = async () => {
    setCollectErr("");
    try {
      await api.tacCancelCollect(incidentId);
      if (alive.current) await readState();
    } catch (e) {
      if (alive.current) setCollectErr(tacError(e, CANCEL_FAILED));
    }
  };

  const runDownload = async () => {
    setBundleErr(""); setBundleNote("");
    const name = bundleFileName(info?.incident_ref || incidentId, bundleProfile);
    try {
      await api.tacDownloadBundle(incidentId, bundleProfile, name);
      if (alive.current) { setBundleNote(`The redacted bundle was saved as ${name}.`); await readState(); }
    } catch (e) {
      if (alive.current) setBundleErr(tacError(e, BUNDLE_FAILED));
    }
  };

  const openCaseForm = async (connector: TacConnectorInfo) => {
    setCaseErr(""); setCaseNote(""); setCaseResult(null); setCaseBusy(true);
    try {
      const r = await api.tacCaseForm(incidentId, connector.id);
      if (!alive.current) return;
      setCaseConnector(r.connector ?? connector);
      setCaseForm(r.form);
      setCaseFields({
        title: r.form.title ?? "", severity: r.form.severity ?? "", product: r.form.product ?? "",
        serial_number: r.form.serial_number ?? "", contract_id: r.form.contract_id ?? "",
        contact_name: r.form.contact_name ?? "", contact_email: r.form.contact_email ?? "",
      });
    } catch (e) {
      if (alive.current) { setCaseForm(null); setCaseErr(tacError(e, CASE_FORM_FAILED)); }
    } finally {
      if (alive.current) setCaseBusy(false);
    }
  };

  const submitCase = async () => {
    if (!caseConnector) return;
    setCaseErr(""); setCaseNote(""); setCaseBusy(true);
    try {
      const r = await api.tacCaseSubmit(incidentId, caseConnector.id, { ...caseFields });
      if (!alive.current) return;
      setCaseResult(r.result);
      setCaseNote(
        r.result.case_id
          ? `Case ${r.result.case_id} recorded with ${caseConnector.display}.`
          : `${caseConnector.display} recorded the escalation; it issued no case number.`,
      );
      await readState();
    } catch (e) {
      if (alive.current) setCaseErr(tacError(e, CASE_SUBMIT_FAILED));
    } finally {
      if (alive.current) setCaseBusy(false);
    }
  };

  // ── render ────────────────────────────────────────────────────────────────

  if (infoErr) {
    return (
      <section className="tac-panel card" aria-label="Escalate to TAC">
        <h2 className="tac-h">Escalate to TAC</h2>
        <p className="tac-bad" role="alert">{infoErr}</p>
      </section>
    );
  }
  if (!info) {
    return (
      <section className="tac-panel card" aria-label="Escalate to TAC">
        <h2 className="tac-h">Escalate to TAC</h2>
        <p className="mini-meta" role="status">Reading this incident&apos;s escalation…</p>
      </section>
    );
  }

  const evidence = evidenceLine(classify?.evidence_sources ?? [], classify?.evidence_missing ?? []);
  const planRows = orderedSteps(plan?.steps);
  const bundles = state?.bundles ?? [];
  // Which connectors this DEVICE can use, and which are somebody else's support
  // desk. A Nokia escalation rendered all twelve with a research paragraph each
  // (owner, 2026-09-06); the rest now sit behind one disclosure.
  const caseRows = splitConnectors(info.connectors, dialectVendor(plan?.dialect ?? capture?.dialect ?? ""));
  const bundleBytes = newestBundleBytes(bundles);
  const activeCaptureId = progress?.capture_id ?? "";

  return (
    <section className="tac-panel card" aria-label="Escalate to TAC">
      <div className="tac-head">
        <h2 className="tac-h">Escalate to TAC</h2>
        <span className="mini-meta tac-ver">Issue catalogue {info.catalog_version}</span>
      </div>

      {/* ── step 1: start ────────────────────────────────────────────────── */}
      {!started && (
        <div className="tac-start">
          <p className="mini-meta">{info.state_note || NOT_ESCALATED_NOTE}</p>
          <button type="button" className="btn accent" onClick={() => { void runClassify(); }} disabled={classifying}>
            {classifying ? "Classifying…" : "Escalate to TAC"}
          </button>
          {classErr && <p className="tac-bad" role="alert">{classErr}</p>}
        </div>
      )}

      {/* ── step 2: captures ─────────────────────────────────────────────── */}
      {started && (
        <section className="tac-step" aria-labelledby="tac-captures-h" data-testid="tac-captures">
          <h3 id="tac-captures-h" className="tac-step-h">Captures</h3>

          <div className="tac-row">
            <label className="tac-field">
              <span>Device</span>
              <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
                <option value="">Choose the device…</option>
                {(info.devices ?? []).filter((d) => !devices.some((x) => x.id === d)).map((d) => (
                  <option key={`aff-${d}`} value={d}>{d}</option>
                ))}
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>{d.name || d.id}{d.address ? ` — ${d.address}` : ""}</option>
                ))}
              </select>
            </label>
            <span className="mini-meta" data-testid="tac-device-note">
              {devicesErr || (planning ? "Reading this platform…" : plan?.dialect_display || plan?.dialect || "")}
            </span>
          </div>
          {planErr && <p className="tac-bad" role="alert">{planErr}</p>}

          {!plan ? (
            <p className="tac-empty" role="status">{CAPTURES_NEED_DEVICE}</p>
          ) : (
            <>
              {plan.has_plan === false && (
                <p className="tac-bad" role="status" data-testid="tac-no-plan">
                  {plan.note || NO_AUTHORED_PLAN_NOTE}
                </p>
              )}
              {rows.length === 0 ? (
                <p className="tac-empty" role="status">{CAPTURES_NONE}</p>
              ) : (
                <ul className="tac-captures" data-testid="tac-capture-rows">
                  {rows.map((c) => (
                    <CaptureRow
                      key={c.id}
                      capture={c}
                      selected={selected?.id === c.id}
                      open={Boolean(expanded[c.id])}
                      status={captureRowStatus(c.id, activeCaptureId, progress)}
                      percent={c.id === activeCaptureId ? captureBarPercent(progress) : 100}
                      failed={failedCommands(c.id, activeCaptureId, progress)}
                      onPick={() => setSelectedId(c.id)}
                      onToggle={() => setExpanded((m) => ({ ...m, [c.id]: !m[c.id] }))}
                    />
                  ))}
                </ul>
              )}

              <div className="tac-row">
                <label className="tac-field">
                  <span>Upload your own</span>
                  <input
                    type="file"
                    accept={UPLOAD_ACCEPT}
                    data-testid="tac-upload"
                    onChange={(e) => { void onUpload(e.target.files?.[0]); }}
                  />
                </label>
                <span className="mini-meta">{uploading ? "Reading the file…" : UPLOAD_FORMATS_LINE}</span>
              </div>
              {refusals.length > 0 && (
                <ul className="tac-refusals" role="alert" data-testid="tac-upload-refusals">
                  {refusals.slice(0, ROW_RENDER_CAP).map((r) => (
                    <li key={`ref-${r.line}-${r.command}`}>{refusalLine(r)}</li>
                  ))}
                </ul>
              )}
              {uploadErr && <p className="tac-bad" role="alert" data-testid="tac-upload-error">{uploadErr}</p>}
              {savedErr && <p className="tac-bad" role="alert">{savedErr}</p>}

              {selected?.source === "uploaded" && (
                <div className="tac-row" data-testid="tac-capture-save">
                  <label className="tac-field">
                    <span>Template name</span>
                    <input
                      type="text"
                      maxLength={120}
                      value={saveName}
                      onChange={(e) => setSaveName(e.target.value)}
                      data-testid="tac-capture-name"
                    />
                  </label>
                  <button
                    type="button"
                    className="btn"
                    disabled={saving}
                    onClick={() => { void saveCapture(); }}
                    data-testid="tac-capture-save-btn"
                  >
                    {saving ? "Saving…" : "Save as template"}
                  </button>
                </div>
              )}
              {saveErr && <p className="tac-bad" role="alert" data-testid="tac-capture-save-error">{saveErr}</p>}
              {saveNote && <p className="fact-line" role="status" data-testid="tac-capture-save-note">{saveNote}</p>}

              <div className="tac-actions">
                <button
                  type="button"
                  className="btn accent"
                  onClick={() => { void runCollect(); }}
                  disabled={collectBusy || running || !info.can_collect || rows.length === 0}
                  title={info.can_collect ? undefined : info.collect_note}
                >
                  {running ? "Collecting…" : "Start the collection"}
                </button>
                <button type="button" className="btn" onClick={() => { void runCancel(); }} disabled={!running}>
                  Stop
                </button>
              </div>
              {!info.can_collect && (
                <p className="tac-bad" role="status" data-testid="tac-collect-note">{info.collect_note}</p>
              )}
              {collectErr && <p className="tac-bad" role="alert" data-testid="tac-collect-error">{collectErr}</p>}

              {/* The paste path, and ONLY where the gateway could not collect. */}
              {showPaste && (
                <div className="tac-paste" data-testid="tac-paste">
                  <h4 className="tac-section-h">Paste missing output</h4>
                  <p className="mini-meta tac-note">{PASTE_INVITE}</p>
                  <div className="tac-row">
                    <label className="tac-field">
                      <span>Output</span>
                      <select
                        value={pasteIntent}
                        data-testid="tac-paste-picker"
                        onChange={(e) => setPasteIntent(e.target.value)}
                      >
                        {missing.slice(0, ROW_RENDER_CAP).map((s) => (
                          <option key={`p-${s.intent}`} value={s.intent} title={stepTooltip(s)}>
                            {pasteOptionLabel(s)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <span className="mini-meta" data-testid="tac-paste-count">
                      {missingOutputsLine(missing.length, boundTotal)}
                    </span>
                  </div>
                  <textarea
                    rows={5}
                    maxLength={MAX_PASTE_CHARS}
                    value={pasteText}
                    aria-label="Pasted output"
                    onChange={(e) => setPasteText(e.target.value)}
                  />
                  <div className="tac-actions">
                    <button
                      type="button"
                      className="btn"
                      disabled={collectBusy || pasteText.trim() === "" || pasteIntent === ""}
                      onClick={() => { void addPastedOutput(); }}
                    >
                      {collectBusy ? "Filing…" : "Add output"}
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>
      )}

      {/* ── step 3: bundle ───────────────────────────────────────────────── */}
      {started && plan && (
        <section className="tac-step" aria-labelledby="tac-bundle-h">
          <h3 id="tac-bundle-h" className="tac-step-h">Bundle</h3>
          {/* ONE line, a profile, a button (owner, 2026-09-06). The redaction
              promise is made once, here, where the file that carries it is
              built. The server's own full promise is not paraphrased out of
              existence — it rides on this line's tooltip, and the (i) answers
              what "redacted" means from the authored corpus. */}
          <p className="mini-meta tac-note" data-testid="tac-redaction" title={plan.redaction_note}>
            {REDACTION_SHORT}
            <AskIris topic="tac.bundle-redaction" label="masked in the bundle" />
          </p>
          {!capture ? (
            <p className="fact-line" role="status">{NO_CAPTURE_YET}</p>
          ) : (
            <>
              <div className="tac-actions">
                <label className="tac-field">
                  <span>Profile</span>
                  <select value={bundleProfile} onChange={(e) => setBundleProfile(e.target.value)}>
                    {BUNDLE_PROFILES.map((p) => (
                      <option key={p.id} value={p.id}>{p.label} — {p.hint}</option>
                    ))}
                  </select>
                </label>
                <button type="button" className="btn accent" onClick={() => { void runDownload(); }}>
                  Download the redacted bundle
                </button>
              </div>
              {bundleErr && <p className="tac-bad" role="alert">{bundleErr}</p>}
              {bundleNote && <p className="fact-line" role="status">{bundleNote}</p>}
            </>
          )}
          <h4 className="tac-section-h">Built bundles</h4>
          {bundles.length === 0 ? (
            <p className="tac-empty">{NO_BUNDLE_YET}</p>
          ) : (
            <ul className="tac-bundles">
              {bundles.map((b) => (
                <li key={b.name}>
                  <code className="tac-cmd">{b.name}</code>{" "}
                  <span className="mini-meta">{humanBytes(b.bytes)} · {b.profile} profile · {b.created_at}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* ── step 4: open the case ────────────────────────────────────────── */}
      {started && plan && (
        <section className="tac-step" aria-labelledby="tac-case-h">
          <h3 id="tac-case-h" className="tac-step-h">Open the case</h3>
          <p className="mini-meta tac-note">{CASE_HUMAN_APPROVED}</p>
          {(info.connectors ?? []).length === 0 ? (
            <p className="tac-empty">
              {NO_CASE_CONNECTOR}
              <AskIris topic="tac.case-connector" label="No case connector" />
            </p>
          ) : (
            <>
              <ul className="tac-connectors" data-testid="tac-conn-rows">
                {caseRows.rows.map((c) => (
                  <ConnectorRow
                    key={c.id} info={c} bundleBytes={bundleBytes} busy={caseBusy}
                    onOpen={() => { void openCaseForm(c); }}
                  />
                ))}
              </ul>
              {caseRows.others.length > 0 && (
                <details className="tac-fold" data-testid="tac-conn-others">
                  <summary>{showAllConnectorsLabel(caseRows.others.length)}</summary>
                  <ul className="tac-connectors">
                    {caseRows.others.map((c) => (
                      <ConnectorRow
                        key={c.id} info={c} bundleBytes={bundleBytes} busy={caseBusy}
                        onOpen={() => { void openCaseForm(c); }}
                      />
                    ))}
                  </ul>
                </details>
              )}
            </>
          )}
          {caseErr && <p className="tac-bad" role="alert" data-testid="tac-case-error">{caseErr}</p>}

          {caseForm && caseConnector && (
            <div className="tac-case" data-testid="tac-case-form">
              <h4 className="tac-section-h">{caseConnector.display} — review before sending</h4>
              <p className="mini-meta tac-note">
                {caseForm.bundle_name} · {humanBytes(caseForm.bundle_bytes)} · {caseForm.profile} profile
                {caseConnector.configured ? "" : ` · ${connectorStatusNote(caseConnector)}`}
              </p>
              <div className="tac-form">
                {CASE_FIELD_LABEL.map(({ key, label }) => {
                  const required = isMissingField(caseForm, key);
                  return (
                    <label className={`tac-field${required ? " req" : ""}`} key={key}>
                      <span>{label}{required ? " — the vendor requires this" : ""}</span>
                      <input
                        type="text"
                        maxLength={200}
                        required={required}
                        aria-required={required}
                        value={caseFields[key]}
                        onChange={(e) => setCaseFields((f) => ({ ...f, [key]: e.target.value }))}
                      />
                    </label>
                  );
                })}
              </div>
              <label className="tac-field">
                <span>Case text</span>
                <textarea className="tac-portal" rows={10} readOnly value={caseForm.portal_text} />
              </label>
              <div className="tac-actions">
                <button
                  type="button"
                  className="btn"
                  onClick={() => { void navigator.clipboard?.writeText(caseForm.portal_text); setCaseNote("The case text was copied."); }}
                >
                  Copy the case text
                </button>
                {caseForm.portal_url && (
                  <a className="btn" href={caseForm.portal_url} target="_blank" rel="noreferrer noopener">
                    Open the vendor portal
                  </a>
                )}
                <button
                  type="button"
                  className="btn accent"
                  disabled={caseBusy || !hasCapability(caseConnector, "create")}
                  onClick={() => { void submitCase(); }}
                >
                  {caseBusy ? "Opening…" : "Open the case"}
                </button>
              </div>
              {!hasCapability(caseConnector, "create") && (
                <p className="mini-meta tac-note">{connectorCapabilityLine(caseConnector)}</p>
              )}
            </div>
          )}

          {caseNote && <p className="mini-meta tac-note" role="status">{caseNote}</p>}
          {caseResult && (
            <p className="mini-meta tac-note" data-testid="tac-case-result">
              {caseResult.attached ? "The bundle was attached." : caseResult.attach_note || "The bundle was not attached."}
              {caseResult.case_url ? " " : ""}
              {caseResult.case_url && (
                <a href={caseResult.case_url} target="_blank" rel="noreferrer noopener">Open the case</a>
              )}
            </p>
          )}
        </section>
      )}

      {/* ── behind the scenes ────────────────────────────────────────────────
          ONE control (owner, 2026-09-06: "Give an option to look what is
          happening behind the scene which you are showing it on screen now").
          It carries what the panel used to print inline: the class it chose and
          the evidence rows that scored it, the commands with their sources and
          verification state, and the collection log. The body is MOUNTED only
          while open — what the escalation step does not show is not in the
          document at all, rather than hidden by a stylesheet. */}
      {started && (
        <section className="tac-step" data-testid="tac-behind">
          <button
            type="button"
            className="tac-behind-toggle"
            aria-expanded={behindOpen}
            onClick={() => setBehindOpen((v) => !v)}
            data-testid="tac-behind-toggle"
          >
            {behindOpen ? "▾ " : "▸ "}{BEHIND_LABEL}
          </button>

          {behindOpen && (
            <div className="tac-behind-body" data-testid="tac-behind-body">
              {classification && (
                <>
                  <h4 className="tac-section-h">Issue class</h4>
                  <p className="tac-class-title">
                    <strong>{classification.title}</strong>{" "}
                    <code className="tac-id">{classification.class_id}</code>{" "}
                    <span className={`badge${classification.classified ? "" : " tac-unsure"}`}>
                      {classification.classified ? "matched the evidence" : "nothing scored"}
                    </span>
                  </p>
                  {classificationNote(classification) && (
                    <p className="mini-meta tac-note">{classificationNote(classification)}</p>
                  )}
                  {classification.tac_first_look && (
                    <p className="mini-meta tac-note">
                      <strong>What TAC opens first:</strong> {classification.tac_first_look}
                    </p>
                  )}
                  {classification.why.length > 0 ? (
                    <ul className="tac-why">
                      {classification.why.map((r) => (
                        <li key={`${r.kind}-${r.ref}`}>{reasonLine(r)}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="fact-line">No evidence row scored this class.</p>
                  )}
                  {classification.alternatives.length > 0 && (
                    <ul className="tac-alts">
                      {classification.alternatives.map((a) => (
                        <li key={a.class_id}>
                          <span className="tac-alt-t">{a.title}</span>{" "}
                          <code className="tac-id">{a.class_id}</code>{" "}
                          <span className="mini-meta">score {a.score}</span>
                          {a.why.length > 0 && (
                            <span className="mini-meta"> — {a.why.map(reasonLine).join(" · ")}</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                  {classify?.evidence_sources && (
                    <p className="fact-line" data-testid="tac-evidence">
                      {evidence.on}
                      {evidence.without ? ` ${evidence.without}` : ""}
                    </p>
                  )}
                  <div className="tac-row">
                    {(classify?.classes?.length ?? 0) > 0 && (
                      <label className="tac-field">
                        <span>Issue class</span>
                        <select
                          value={classOverride || classification.class_id}
                          onChange={(e) => setClassOverride(e.target.value)}
                        >
                          {classify!.classes.map((c) => (
                            <option key={c.id} value={c.id}>{c.title} — {c.id}</option>
                          ))}
                        </select>
                      </label>
                    )}
                    <button type="button" className="btn" onClick={() => { void runClassify(); }} disabled={classifying}>
                      {classifying ? "Classifying…" : "Classify again"}
                    </button>
                  </div>
                  {classErr && <p className="tac-bad" role="alert">{classErr}</p>}
                </>
              )}

              <h4 className="tac-section-h">Commands</h4>
              <div className="tac-form">
                {([
                  ["interface", "Interface"], ["peer", "Peer"], ["prefix", "Prefix"],
                  ["vrf", "VRF"], ["router_id", "Router id"], ["area", "Area"],
                ] as [keyof TacTarget, string][]).map(([key, label]) => (
                  <label className="tac-field" key={key}>
                    <span>{label}</span>
                    <input
                      type="text"
                      maxLength={256}
                      value={target[key] ?? ""}
                      onChange={(e) => setTarget((t) => ({ ...t, [key]: e.target.value }))}
                    />
                  </label>
                ))}
                <label className="tac-check">
                  <input
                    type="checkbox"
                    checked={includeOptional}
                    onChange={(e) => setIncludeOptional(e.target.checked)}
                  />
                  <span>Include the optional captures</span>
                </label>
                <div className="tac-actions">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => { void runPlan(); }}
                    disabled={planning || !deviceId.trim()}
                    data-testid="tac-rebuild"
                  >
                    {planning ? "Rebuilding…" : "Rebuild"}
                  </button>
                </div>
              </div>

              {plan && (
                <div className="tac-plan" data-testid="tac-plan">
                  <p className="tac-plan-head" title={planVersionTitle(plan)}>{planHeadline(plan)}</p>
                  {planRows.length > 0 && (
                    <>
                      <div className="tac-plan-scroll">
                        <table className="tac-plan-table" data-testid="tac-plan-table">
                          <thead>
                            <tr>
                              <th scope="col" className="tac-col-n">#</th>
                              <th scope="col">What it collects</th>
                              <th scope="col">Command</th>
                              <th scope="col">Status</th>
                              <th scope="col" className="tac-col-ref"><span className="tac-sr">Reference</span></th>
                            </tr>
                          </thead>
                          <tbody>
                            {planRows.slice(0, ROW_RENDER_CAP).map((s, i) => (
                              <PlanRow key={`${s.section}-${s.intent}`} step={s} n={i + 1} />
                            ))}
                          </tbody>
                        </table>
                      </div>
                      {planRows.length > ROW_RENDER_CAP && (
                        <p className="tac-plan-legend">{cappedNote(ROW_RENDER_CAP, planRows.length, "steps")}</p>
                      )}
                      <p className="tac-plan-legend" data-testid="tac-plan-legend">{PLAN_LEGEND}</p>
                    </>
                  )}

                  {plan.topology.length > 0 && (
                    <details className="tac-fold" data-testid="tac-topology">
                      <summary>{topologyLine(plan.topology.length)}</summary>
                      <ul className="tac-fold-list">
                        {plan.topology.slice(0, ROW_RENDER_CAP).map((t, i) => (
                          <li key={`${t.kind}-${t.ref}-${i}`} title={t.detail || t.kind}>{t.ref}</li>
                        ))}
                      </ul>
                    </details>
                  )}

                  {plan.unbound.length > 0 && (
                    <details className="tac-fold" data-testid="tac-unbound">
                      <summary>{unavailableLine(plan.unbound.length, plan.dialect_display || plan.dialect)}</summary>
                      <ul className="tac-fold-list">
                        {plan.unbound.slice(0, ROW_RENDER_CAP).map((s) => (
                          <li key={`ub-${s.intent}`} title={`${stepTooltip(s)} · ${unboundReason(s)}`}>{s.title}</li>
                        ))}
                      </ul>
                    </details>
                  )}
                </div>
              )}

              <h4 className="tac-section-h">Collection log</h4>
              {state?.job ? (
                <div className="tac-job" data-testid="tac-job">
                  <p className="fact-line">
                    {state.job.done} of {state.job.total} commands · {state.job.status}
                    {state.job.error ? ` · ${state.job.error}` : ""}
                  </p>
                  <ul className="tac-progress">
                    {state.job.progress.slice(-ROW_RENDER_CAP).map((p, i) => (
                      <li key={`${p.index}-${p.phase}-${i}`} className={`tac-prog ${p.phase}`}>
                        <span className="tac-prog-i">{p.index + 1}/{p.total}</span>
                        <code className="tac-id">{p.intent}</code>
                        <code className="tac-cmd">{p.command}</code>
                        <span className="tac-prog-p">{phaseLabel(p.phase)}</span>
                        <span className="mini-meta">
                          {p.error ? p.error : p.bytes != null ? humanBytes(p.bytes) : ""}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="tac-empty">Nothing has been collected yet.</p>
              )}

              {capture && (
                <div className="tac-capture" data-testid="tac-capture">
                  <p className="fact-line">
                    {capture.commands.length} command(s) · {humanBytes(capture.total_bytes)} from{" "}
                    {capture.hostname || capture.device_id}
                    {capture.stopped ? ` · stopped: ${capture.stopped}` : ""}
                  </p>
                  {capture.commands.slice(0, ROW_RENDER_CAP).map((c) => (
                    <details className="tac-out" key={`cap-${c.intent}`}>
                      <summary>
                        <code className="tac-cmd">{c.command || c.intent}</code>{" "}
                        <span className="mini-meta">
                          {c.error ? c.error : `${humanBytes(c.bytes)}`}
                          {verifiedLabel(c.verified) ? ` · ${verifiedLabel(c.verified)}` : ""}
                        </span>
                      </summary>
                      {c.output ? (
                        <pre className="tac-pre">{c.output}</pre>
                      ) : (
                        <p className="fact-line">
                          {c.error || "The device returned nothing for this command."}
                        </p>
                      )}
                    </details>
                  ))}
                </div>
              )}
            </div>
          )}
        </section>
      )}
    </section>
  );
}

/**
 * One capture, as one row (owner, 2026-09-06).
 *
 * Four things and nothing else: the name, how many commands it holds, a
 * coloured status, and a chevron. The commands themselves are HIDDEN until the
 * chevron is used — a customer choosing between three named sets does not need
 * forty command lines on screen to do it.
 *
 * Under a partial or failed row: ONLY the commands that failed, in the error
 * colour, each with its plain reason. What succeeded is in the bundle.
 */
function CaptureRow({ capture, selected, open, status, percent, failed, onPick, onToggle }: {
  capture: TacCommandCapture;
  selected: boolean;
  open: boolean;
  status: TacCaptureStatus;
  percent: number;
  failed: TacCommandStatus[];
  onPick: () => void;
  onToggle: () => void;
}) {
  return (
    <li className={`tac-capture-row${selected ? " on" : ""}`} data-testid={`tac-capture-${capture.id}`}>
      <div className="tac-capture-head">
        <button
          type="button"
          className="tac-capture-toggle"
          aria-expanded={open}
          aria-label={`Commands in ${capture.name}`}
          onClick={onToggle}
        >
          {open ? "▾" : "▸"}
        </button>
        <label className="tac-capture-pick">
          <input type="radio" name="tac-capture" checked={selected} onChange={onPick} />
          <span className="tac-capture-name">{capture.name}</span>
        </label>
        <span className="mini-meta">{CAPTURE_SOURCE_LABEL[capture.source]}</span>
        <span className="fact-line">{commandCountLine(capture.commands.length)}</span>
        <span className="tac-capture-status">
          <span className={`tac-capture-track tac-capture-${status}`}>
            <span className="tac-capture-bar" style={{ width: `${percent}%` }} />
          </span>
          <span className={`tac-chip tac-chip-${status}`}>{CAPTURE_STATUS_LABEL[status]}</span>
        </span>
      </div>
      {open && (
        <ol className="tac-capture-cmds" data-testid={`tac-capture-cmds-${capture.id}`}>
          {capture.commands.slice(0, ROW_RENDER_CAP).map((c, i) => (
            <li key={`${capture.id}-${i}`}><code className="tac-cmd">{c.command}</code></li>
          ))}
        </ol>
      )}
      {failed.length > 0 && (
        <ul className="tac-capture-fails" data-testid={`tac-capture-failed-${capture.id}`}>
          {failed.slice(0, ROW_RENDER_CAP).map((f, i) => (
            <li key={`${capture.id}-f-${i}`} className="tac-capture-fail">{failedCommandLine(f)}</li>
          ))}
        </ul>
      )}
    </li>
  );
}

/** The plan's rows, in the order the collection runs them: the vendor baseline
 *  first, then this issue's own checks, then anything optional. Topology is
 *  model context, not a command, so it never becomes a row. */
function orderedSteps(steps: TacStep[] | undefined): TacStep[] {
  const rows = (steps ?? []).filter((s) => s.section !== "topology");
  return rows
    .map((s, i) => ({ s, i, rank: Math.max(0, SECTION_ORDER.indexOf(s.section)) }))
    .sort((a, b) => (a.rank === b.rank ? a.i - b.i : a.rank - b.rank))
    .map((x) => x.s);
}

/**
 * One connector, as one row (owner, 2026-09-06: "what's all this").
 *
 * Four things and nothing else: the name, one plain-words sentence about what
 * it does, one chip for the state, and — only when the bundle would not fit —
 * the ceiling. The connector's standing vendor research (attachment limits,
 * API caveats, the dated negative) is a paragraph per connector and used to
 * print here, twelve deep; it is now behind the row's (i), answered from
 * ai/skills/explain/tac.connector.<id>.md, and on Administration → Ticket
 * delivery where the credentials are brought.
 *
 * "Not configured" is a STATE with a next step, and it links to where that step
 * is taken. "Unavailable" is an ERROR: the stored configuration could not be
 * read, the row says so with the cause the server named, and the server logs it.
 */
function ConnectorRow({ info, bundleBytes, busy, onOpen }: {
  info: TacConnectorInfo;
  bundleBytes: number;
  busy: boolean;
  onOpen: () => void;
}) {
  const state = connectorState(info);
  const note = connectorStatusNote(info);
  const over = ceilingSuffix(info, bundleBytes);
  const usable = state === "ready" || state === "attach-only";
  return (
    <li className={`tac-conn${usable ? "" : " off"}`} data-testid={`tac-conn-${info.id}`}>
      <button
        type="button"
        className="btn"
        disabled={!usable || busy}
        aria-disabled={!usable}
        onClick={onOpen}
      >
        {info.display}
      </button>
      <span className="mini-meta">{connectorCapabilityLine(info)}</span>
      <span className={`tac-chip tac-chip-${state}`}>{CONNECTOR_CHIP[state]}</span>
      {over && <span className="mini-meta tac-over">{over}</span>}
      {state === "not-configured" && (
        <a className="mini-meta tac-conn-link" href={TICKET_DELIVERY_ROUTE} title={note}>
          {TICKET_DELIVERY_LABEL}
        </a>
      )}
      {state === "unavailable" && (
        <span className="mini-meta tac-bad" role="alert">{note}</span>
      )}
      <AskIris topic={connectorTopic(info.id)} label={info.display} />
    </li>
  );
}

/** One row of the command plan: the step number, what it collects in plain
 *  words, the command, one chip, and at most one reference.
 *
 *  It lives BEHIND the "What Correlix is doing" control now
 *  (docs/design/TAC_CAPTURES_2026-09-06.md): the escalation step shows captures,
 *  and the intent ids, sources and verification state are the engine's working,
 *  available on demand rather than in the customer's way. */
function PlanRow({ step, n }: { step: TacStep; n: number }) {
  const status = stepStatus(step.verified);
  const ref = stepReference(step);
  return (
    <tr className="tac-plan-row" title={stepTooltip(step)}>
      <td className="tac-col-n">{n}</td>
      <td className="tac-col-what">{step.title}</td>
      <td className="tac-col-cmd"><code>{step.command || ""}</code></td>
      <td className="tac-col-status">
        <span className={`tac-chip tac-chip-${status}`}>{STATUS_CHIP[status]}</span>
      </td>
      <td className="tac-col-ref">
        {ref ? (
          <a
            className="tac-ref"
            href={ref.url}
            target="_blank"
            rel="noreferrer noopener"
            title={ref.title}
            aria-label={`Vendor page for ${step.title}`}
          >
            &#8599;
          </a>
        ) : null}
      </td>
    </tr>
  );
}
