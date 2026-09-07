// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// TacEscalationPanel — the TAC escalation flow, one panel, incident-first.
//
// Design of record: docs/design/TAC_ESCALATION_2026-09-05.md §1. It replaces the
// manual protocol-diagnostics bench: an operator no longer picks a protocol, an
// issue and a device and presses "analyze". They press ONE button under the
// verdict and Correlix does the legwork in six visible steps:
//
//   1. verdict          — RcaCaseHeader, above this panel (not ours)
//   2. class + why      — what Correlix thinks this is, the exact evidence rows
//                         that scored it, the alternatives, and an override
//   3. plan preview     — the commands, BEFORE anything runs, with the size/time
//                         estimate and what will be redacted
//   4. collect          — read-only over the SSH gateway, live per command; or
//                         paste the output when the platform has no plan / the
//                         deployment has no runner
//   5. bundle           — the redacted zip the SERVER builds
//   6. open case        — a pre-filled form a PERSON submits
//
// HONESTY (the reason the feature exists). Nothing here is filled in to look
// finished. `classified:false` shows the server's own note and never an invented
// class. `has_plan:false` says this platform has no authored command set. An
// unbound intent is counted and named, with its reason on its tooltip. A
// `doc_claimed` command is chipped "From vendor docs". A 503 on collect renders the server's own
// collect_note and leaves the paste path open. A connector with no credentials
// is greyed with its own note and cannot be pressed into a case.
//
// SECURITY (§3 zero trust / §15 untrusted output). Command output, the problem
// statement, connector notes and case text are all remote-authored. Every one of
// them is rendered as an escaped React text node — there is no innerHTML and no
// dangerouslySetInnerHTML in this file. The download name is built from a closed
// character set, so a remote string cannot steer a file path.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  type Device,
  type TacCaseForm,
  type TacCaseResult,
  type TacClassifyResponse,
  type TacConnectorInfo,
  type TacCollectRequest,
  type TacLineVerdict,
  type TacPlan,
  type TacState,
  type TacStateResponse,
  type TacStep,
  type TacTarget,
  type TacTemplate,
} from "../../services/api";
import {
  BUNDLE_FAILED,
  BUNDLE_PROFILES,
  CANCEL_FAILED,
  CUSTOM_COMMAND_NOTE,
  CASE_FORM_FAILED,
  CASE_HUMAN_APPROVED,
  CASE_SUBMIT_FAILED,
  CLASSIFY_FAILED,
  CONNECTOR_CHIP,
  DEVICES_FAILED,
  MAX_PASTE_CHARS,
  MAX_REVIEW_COMMANDS,
  NOT_ESCALATED_NOTE,
  NO_AUTHORED_PLAN_NOTE,
  NO_BUNDLE_YET,
  NO_CAPTURE_YET,
  NO_CASE_CONNECTOR,
  PASTE_INVITE,
  PLAN_FAILED,
  PLAN_LEGEND,
  PLAN_NEEDS_DEVICE,
  REDACTION_SHORT,
  REVIEW_EMPTY,
  REVIEW_INTRO,
  REVIEW_POLICY_NOTE,
  REVIEW_REFUSED,
  ROW_RENDER_CAP,
  SECTION_ORDER,
  STATE_READ_FAILED,
  STATUS_CHIP,
  TEMPLATES_FAILED,
  TEMPLATE_NEEDS_NAME,
  TEMPLATE_SAVE_FAILED,
  TICKET_DELIVERY_LABEL,
  TICKET_DELIVERY_ROUTE,
  VALIDATE_FAILED,
  boundSteps,
  buildPlanRequest,
  buildReviewedSteps,
  buildTemplateWrite,
  bundleFileName,
  cappedNote,
  ceilingSuffix,
  classificationNote,
  collectErrorMessage,
  connectorCapabilityLine,
  connectorState,
  connectorStatusNote,
  connectorTopic,
  dialectVendor,
  editSummary,
  evidenceLine,
  hasCapability,
  humanBytes,
  isCollecting,
  isMissingField,
  missingOutputs,
  missingOutputsLine,
  moveCommand,
  newestBundleBytes,
  originLabel,
  pasteOffered,
  pasteOptionLabel,
  phaseLabel,
  planCommands,
  planHeadline,
  planVersionTitle,
  reasonLine,
  reviewChanged,
  showAllConnectorsLabel,
  splitConnectors,
  stepReference,
  stepStatus,
  stepTooltip,
  tacError,
  templateLabel,
  topologyLine,
  unavailableLine,
  unboundReason,
  verdictLine,
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

  // ── the command review (tracker 250) ──────────────────────────────────────
  // reviewCmds is the operator's working list, seeded from the plan and edited
  // freely. verdicts is what the SERVER said about it — the client renders that
  // and decides nothing about what may run.
  const [reviewCmds, setReviewCmds] = useState<string[]>([]);
  const [verdicts, setVerdicts] = useState<TacLineVerdict[]>([]);
  const [reviewErr, setReviewErr] = useState("");
  const [checking, setChecking] = useState(false);
  const [templates, setTemplates] = useState<TacTemplate[]>([]);
  const [templatesErr, setTemplatesErr] = useState("");
  const [templateId, setTemplateId] = useState("");
  const [saveName, setSaveName] = useState("");
  const [saveDesc, setSaveDesc] = useState("");
  const [saveNote, setSaveNote] = useState("");
  const [saveErr, setSaveErr] = useState("");
  const [saving, setSaving] = useState(false);

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
    setReviewCmds([]); setVerdicts([]); setReviewErr(""); setTemplateId("");
    setSaveName(""); setSaveDesc(""); setSaveNote(""); setSaveErr("");
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

  const runPlan = async () => {
    setPlanErr("");
    if (!deviceId.trim()) { setPlanErr(PLAN_NEEDS_DEVICE); return; }
    setPlanning(true);
    try {
      const classId = classOverride || classification?.class_id || "";
      await api.tacPlan(incidentId, buildPlanRequest(deviceId, classId, includeOptional, target));
      if (alive.current) await readState();
    } catch (e) {
      if (alive.current) setPlanErr(tacError(e, PLAN_FAILED));
    } finally {
      if (alive.current) setPlanning(false);
    }
  };

  // ── the command review ────────────────────────────────────────────────────

  // The working list is SEEDED from the plan the server built and re-seeded
  // whenever that plan changes (a rebuild, a different device, a different
  // class). An operator's in-progress edit is deliberately discarded then: it
  // was a list for a plan that no longer exists.
  const planKey = plan ? `${plan.id}:${plan.device_id}:${plan.class_id}` : "";
  useEffect(() => {
    if (!plan) { setReviewCmds([]); setVerdicts([]); return; }
    setReviewCmds(planCommands(plan));
    setSaveErr(""); setSaveNote("");
  }, [planKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // The tenant's saved sets for THIS device's dialect, plus Correlix's own. A
  // set written for another vendor is never offered: a list of EOS commands is
  // meaningless at a Junos router.
  const dialect = plan?.dialect ?? "";
  useEffect(() => {
    if (!dialect) { setTemplates([]); return; }
    api.tacTemplates(dialect)
      .then((r) => {
        if (!alive.current) return;
        setTemplates([...(r.defaults ?? []), ...(r.templates ?? [])]);
        setTemplatesErr("");
      })
      .catch((e: unknown) => {
        if (alive.current) { setTemplates([]); setTemplatesErr(tacError(e, TEMPLATES_FAILED)); }
      });
  }, [dialect]);

  // Live per-line validation. It is DEBOUNCED and it is advisory: the server
  // re-validates the same list at collect, so a check that failed to run can
  // never let a refused command through — it only means the operator finds out
  // one step later.
  useEffect(() => {
    if (!dialect || reviewCmds.length === 0) { setVerdicts([]); return; }
    let cancelled = false;
    const id = setTimeout(() => {
      setChecking(true);
      api.tacTemplateValidate(dialect, reviewCmds)
        .then((r) => {
          if (cancelled || !alive.current) return;
          setVerdicts(r.validation?.lines ?? []);
          setReviewErr("");
        })
        .catch((e: unknown) => {
          if (cancelled || !alive.current) return;
          setVerdicts([]);
          setReviewErr(tacError(e, VALIDATE_FAILED));
        })
        .finally(() => { if (!cancelled && alive.current) setChecking(false); });
    }, 400);
    return () => { cancelled = true; clearTimeout(id); };
  }, [dialect, reviewCmds]);

  const refused = verdicts.filter((v) => !v.ok).length;
  const reviewEdited = reviewChanged(plan, reviewCmds);

  const loadTemplate = (id: string) => {
    setTemplateId(id);
    if (!id) return;
    const t = templates.find((x) => x.id === id);
    if (!t) return;
    setReviewCmds(t.steps.map((st) => st.command));
    setSaveNote(`Loaded “${t.name}” — ${templateLabel(t)}.`);
  };

  const saveTemplate = async () => {
    setSaveErr(""); setSaveNote("");
    if (!saveName.trim()) { setSaveErr(TEMPLATE_NEEDS_NAME); return; }
    if (reviewCmds.filter((c) => c.trim()).length === 0) { setSaveErr(REVIEW_EMPTY); return; }
    setSaving(true);
    try {
      const basedOn = templateId.startsWith("correlix:") ? templateId : "";
      const r = await api.tacTemplateSave(
        buildTemplateWrite(dialect, saveName, saveDesc, basedOn, reviewCmds),
      );
      if (!alive.current) return;
      setSaveNote(`Saved “${r.template.name}” for ${dialect} — it will be offered on the next ${dialect} escalation.`);
      setSaveName(""); setSaveDesc("");
      const list = await api.tacTemplates(dialect);
      if (alive.current) setTemplates([...(list.defaults ?? []), ...(list.templates ?? [])]);
    } catch (e) {
      if (alive.current) setSaveErr(tacError(e, TEMPLATE_SAVE_FAILED));
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
      // The reviewed list travels ONLY when it differs from the plan or came
      // from a template — otherwise the server runs the plan it already holds,
      // and the bundle honestly records that nothing was edited.
      if (reviewEdited || templateId) {
        body.steps = buildReviewedSteps(reviewCmds);
        if (templateId) body.template_id = templateId;
      }
      await api.tacCollect(incidentId, body);
      if (alive.current) await readState();
    } catch (e) {
      if (alive.current) setCollectErr(collectErrorMessage(e, info?.collect_note ?? ""));
    } finally {
      if (alive.current) setCollectBusy(false);
    }
  };

  /** File ONE pasted output for the selected step. The reviewed command list is
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

  const started = Boolean(classification);
  const evidence = evidenceLine(classify?.evidence_sources ?? [], classify?.evidence_missing ?? []);
  const planRows = orderedSteps(plan?.steps);
  const bundles = state?.bundles ?? [];
  // Which connectors this DEVICE can use, and which are somebody else's support
  // desk. A Nokia escalation rendered all twelve with a research paragraph each
  // (owner, 2026-09-06); the rest now sit behind one disclosure.
  const caseRows = splitConnectors(info.connectors, dialectVendor(plan?.dialect ?? capture?.dialect ?? ""));
  const bundleBytes = newestBundleBytes(bundles);

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

      {/* ── step 2: class + why ──────────────────────────────────────────── */}
      {started && classification && (
        <section className="tac-step" aria-labelledby="tac-class-h">
          <h3 id="tac-class-h" className="tac-step-h">Issue class</h3>
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
            <>
              <p className="fact-line">The evidence that scored this class:</p>
              <ul className="tac-why">
                {classification.why.map((r) => (
                  <li key={`${r.kind}-${r.ref}`}>{reasonLine(r)}</li>
                ))}
              </ul>
            </>
          ) : (
            <p className="fact-line">No evidence row scored this class.</p>
          )}

          {classification.alternatives.length > 0 && (
            <>
              <p className="fact-line">Other classes that scored:</p>
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
            </>
          )}

          {classify?.evidence_sources && (
            <p className="mini-meta tac-note" data-testid="tac-evidence">
              {evidence.on}
              {evidence.without ? ` ${evidence.without}` : ""}
            </p>
          )}

          <div className="tac-row">
            {(classify?.classes?.length ?? 0) > 0 ? (
              <div className="tac-field">
                {/* The hint sits OUTSIDE the label: a label that wraps its own
                    help text names the control after both, and the accessible
                    name stops being the field's name. */}
                <label>
                  <span>Change the issue class</span>
                  <select
                    value={classOverride || classification.class_id}
                    onChange={(e) => setClassOverride(e.target.value)}
                  >
                    {classify!.classes.map((c) => (
                      <option key={c.id} value={c.id}>{c.title} — {c.id}</option>
                    ))}
                  </select>
                </label>
                <span className="mini-meta">Override the class if you know better.</span>
              </div>
            ) : (
              <p className="fact-line">The class list arrives with a classification.</p>
            )}
            <button type="button" className="btn" onClick={() => { void runClassify(); }} disabled={classifying}>
              {classifying ? "Classifying…" : "Classify again"}
            </button>
          </div>
          {classErr && <p className="tac-bad" role="alert">{classErr}</p>}
        </section>
      )}

      {/* ── step 3: plan preview ─────────────────────────────────────────── */}
      {started && (
        <section className="tac-step" aria-labelledby="tac-plan-h">
          <h3 id="tac-plan-h" className="tac-step-h">Command plan</h3>
          <div className="tac-form">
            <div className="tac-field">
              <label>
                <span>Device</span>
                <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
                  <option value="">Choose the device…</option>
                  {(info.devices ?? []).filter((d) => !devices.some((x) => x.id === d)).map((d) => (
                    <option key={`aff-${d}`} value={d}>{d} — named by this incident</option>
                  ))}
                  {devices.map((d) => (
                    <option key={d.id} value={d.id}>{d.name || d.id}{d.address ? ` — ${d.address}` : ""}</option>
                  ))}
                </select>
              </label>
              <span className="mini-meta">
                {devicesErr || "The incident's own devices are listed first; any device you can see is selectable."}
              </span>
            </div>
            {([
              ["interface", "Interface"], ["peer", "Peer"], ["prefix", "Prefix"],
              ["vrf", "VRF"], ["router_id", "Router id"], ["area", "Area"],
            ] as [keyof TacTarget, string][]).map(([key, label]) => (
              <label className="tac-field" key={key}>
                <span>{label} (optional)</span>
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
              <span>Include the optional captures (large and slow, off by default)</span>
            </label>
            <div className="tac-actions">
              <button type="button" className="btn accent" onClick={() => { void runPlan(); }} disabled={planning}>
                {planning ? "Building the plan…" : plan ? "Rebuild the plan" : "Build the command plan"}
              </button>
            </div>
          </div>
          {planErr && <p className="tac-bad" role="alert">{planErr}</p>}

          {!plan ? (
            <p className="mini-meta tac-note" role="status">{PLAN_NEEDS_DEVICE}</p>
          ) : (
            <div className="tac-plan" data-testid="tac-plan">
              <p className="tac-plan-head" title={planVersionTitle(plan)}>{planHeadline(plan)}</p>
              {!plan.has_plan && (
                <p className="tac-bad" role="status" data-testid="tac-no-plan">
                  {plan.note || NO_AUTHORED_PLAN_NOTE}
                </p>
              )}

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
        </section>
      )}

      {/* ── step 3b: review the commands (tracker 250) ───────────────────── */}
      {started && plan && (
        <section className="tac-step" aria-labelledby="tac-review-h" data-testid="tac-review">
          <h3 id="tac-review-h" className="tac-step-h">Review the commands</h3>
          <p className="mini-meta tac-note">{REVIEW_INTRO}</p>
          <p className="mini-meta tac-note" data-testid="tac-review-policy">{REVIEW_POLICY_NOTE}</p>

          <div className="tac-row tac-tpl-row">
            <div className="tac-field">
              <label>
                <span>Load a command template</span>
                <select
                  value={templateId}
                  onChange={(e) => loadTemplate(e.target.value)}
                  data-testid="tac-template-picker"
                >
                  <option value="">Correlix&apos;s plan for this incident</option>
                  {templates.map((t) => (
                    <option key={t.id} value={t.id}>{t.name} — {templateLabel(t)}</option>
                  ))}
                </select>
              </label>
              <span className="mini-meta">
                {templatesErr
                  || (templates.length === 0
                    ? `No saved set for ${plan.dialect_display || plan.dialect} yet — build one below.`
                    : `Sets written for ${plan.dialect_display || plan.dialect}. Correlix's own are read-only; save a copy to make it yours.`)}
              </span>
            </div>
            <button
              type="button"
              className="btn"
              onClick={() => { setReviewCmds(planCommands(plan)); setTemplateId(""); setSaveNote(""); }}
              data-testid="tac-review-reset"
            >
              Reset to Correlix&apos;s plan
            </button>
          </div>

          <ol className="tac-review-list" data-testid="tac-review-list">
            {reviewCmds.map((cmd, i) => {
              const v = verdicts[i];
              const bad = v ? !v.ok : false;
              return (
                <li key={`rev-${i}`} className={`tac-review-row${bad ? " bad" : ""}`}>
                  <input
                    type="text"
                    className="tac-review-cmd"
                    aria-label={`Command ${i + 1}`}
                    maxLength={512}
                    value={cmd}
                    onChange={(e) => setReviewCmds((list) => list.map((c, j) => (j === i ? e.target.value : c)))}
                  />
                  <span className="tac-review-actions">
                    <button
                      type="button"
                      className="btn tiny"
                      aria-label={`Move command ${i + 1} up`}
                      disabled={i === 0}
                      onClick={() => setReviewCmds((list) => moveCommand(list, i, i - 1))}
                    >
                      ↑
                    </button>
                    <button
                      type="button"
                      className="btn tiny"
                      aria-label={`Move command ${i + 1} down`}
                      disabled={i === reviewCmds.length - 1}
                      onClick={() => setReviewCmds((list) => moveCommand(list, i, i + 1))}
                    >
                      ↓
                    </button>
                    <button
                      type="button"
                      className="btn tiny"
                      aria-label={`Remove command ${i + 1}`}
                      onClick={() => setReviewCmds((list) => list.filter((_, j) => j !== i))}
                    >
                      Remove
                    </button>
                  </span>
                  {v && (
                    <span className={`mini-meta tac-verdict${bad ? " tac-bad" : ""}`} role={bad ? "alert" : undefined}>
                      {bad && v.family ? <span className="badge tac-family">{v.family}</span> : null}
                      {!bad ? <span className="badge">{originLabel(v)}</span> : null}{" "}
                      {verdictLine(v) || (v.origin === "custom" ? CUSTOM_COMMAND_NOTE : "")}
                    </span>
                  )}
                </li>
              );
            })}
          </ol>

          <div className="tac-actions">
            <button
              type="button"
              className="btn"
              disabled={reviewCmds.length >= MAX_REVIEW_COMMANDS}
              onClick={() => setReviewCmds((list) => [...list, ""])}
              data-testid="tac-review-add"
            >
              Add a command
            </button>
            <span className="mini-meta">
              {reviewCmds.length} of {MAX_REVIEW_COMMANDS} commands
              {checking ? " · checking…" : ""}
            </span>
          </div>

          {refused > 0 && (
            <p className="tac-bad" role="alert" data-testid="tac-review-refused">{REVIEW_REFUSED}</p>
          )}
          {reviewCmds.filter((c) => c.trim()).length === 0 && (
            <p className="tac-bad" role="status">{REVIEW_EMPTY}</p>
          )}
          {reviewErr && <p className="mini-meta tac-note" role="status">{reviewErr}</p>}
          {plan.reviewed && editSummary(plan) && (
            <p className="mini-meta tac-note" data-testid="tac-review-edits">{editSummary(plan)}</p>
          )}

          <details className="tac-tpl-save">
            <summary>Save this set as a template for {plan.dialect_display || plan.dialect}</summary>
            <div className="tac-form">
              <label className="tac-field">
                <span>Template name</span>
                <input
                  type="text"
                  maxLength={120}
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  data-testid="tac-template-name"
                />
              </label>
              <label className="tac-field">
                <span>What it is for (optional)</span>
                <input
                  type="text"
                  maxLength={800}
                  value={saveDesc}
                  onChange={(e) => setSaveDesc(e.target.value)}
                />
              </label>
              <div className="tac-actions">
                <button
                  type="button"
                  className="btn"
                  disabled={saving || refused > 0}
                  onClick={() => { void saveTemplate(); }}
                  data-testid="tac-template-save"
                >
                  {saving ? "Saving…" : "Save as template"}
                </button>
                <span className="mini-meta">
                  Saved for your tenant only, for {plan.dialect_display || plan.dialect}. Every command is checked
                  again on the way in.
                </span>
              </div>
              {saveErr && <p className="tac-bad" role="alert" data-testid="tac-template-error">{saveErr}</p>}
              {saveNote && <p className="mini-meta tac-note" role="status" data-testid="tac-template-note">{saveNote}</p>}
            </div>
          </details>
        </section>
      )}

      {/* ── step 4: collect ──────────────────────────────────────────────── */}
      {started && plan && (
        <section className="tac-step" aria-labelledby="tac-collect-h">
          <h3 id="tac-collect-h" className="tac-step-h">Collect</h3>
          {!info.can_collect && (
            <p className="tac-bad" role="status" data-testid="tac-collect-note">{info.collect_note}</p>
          )}
          <div className="tac-actions">
            <button
              type="button"
              className="btn accent"
              onClick={() => { void runCollect(); }}
              disabled={collectBusy || running || !info.can_collect || refused > 0}
              title={info.can_collect ? undefined : info.collect_note}
            >
              {running ? "Collecting…" : "Start the collection"}
            </button>
            <button type="button" className="btn" onClick={() => { void runCancel(); }} disabled={!running}>
              Stop
            </button>
          </div>
          {collectErr && <p className="tac-bad" role="alert" data-testid="tac-collect-error">{collectErr}</p>}

          {state?.job && (
            <div className="tac-job" role="status" aria-live="polite" data-testid="tac-job">
              <p className="mini-meta">
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
              {state.job.progress.length > ROW_RENDER_CAP && (
                <p className="mini-meta tac-note">
                  {cappedNote(ROW_RENDER_CAP, state.job.progress.length, "progress lines")}
                </p>
              )}
            </div>
          )}

          {capture && (
            <div className="tac-capture" data-testid="tac-capture">
              <p className="mini-meta tac-note">
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
                    <p className="mini-meta tac-note">
                      {c.error || "The device returned nothing for this command."}
                    </p>
                  )}
                </details>
              ))}
            </div>
          )}

          {/* The paste path, and ONLY where the gateway could not collect.
              It used to render one textarea per intent in the whole class —
              72 of them on a Nokia SR Linux plan, labelled with raw intent ids
              for checks Correlix had already said it cannot run. It is now one
              control over the bound steps that still lack output, and the count
              says how much is left. */}
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
        </section>
      )}

      {/* ── step 5: bundle ───────────────────────────────────────────────── */}
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

      {/* ── step 6: open the case ────────────────────────────────────────── */}
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
    </section>
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
 *  What is NOT here is the point (owner, 2026-09-06). The intent id, the
 *  collection stage and the "documented, not verified" caveat used to be
 *  printed on every row; they now live in the row's tooltip and in the single
 *  legend line under the table. The citation list used to be printed in full —
 *  366 links per row on a Nokia SR Linux plan — and is now one small link to
 *  the first page, if the pack cites one at all. */
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
