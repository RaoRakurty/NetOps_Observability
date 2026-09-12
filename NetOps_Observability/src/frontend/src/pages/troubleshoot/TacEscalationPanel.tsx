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
  type TacCaseLink,
  type TacCaseResult,
  type TacClassifyResponse,
  type TacCommandCapture,
  type TacCommandStatus,
  type TacConnectorInfo,
  type TacCollectRequest,
  type TacDryRunCall,
  type TacDryRunReport,
  type TacEscalationRoute,
  type TacPlan,
  type TacProposal,
  type TacState,
  type TacStateResponse,
  type TacStep,
  type TacTarget,
} from "../../services/api";
import TacCaseChip from "../../components/tac/TacCaseChip";
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
  CASE_NUMBER_LABEL,
  UPLOAD_TOKEN_LABEL,
  UPLOAD_TOKEN_HINT,
  needsUploadToken,
  confirmReady,
  unresolvedBlockers,
  capturesHaveRun,
  caseNumberLooksValid,
  caseNumberRefusal,
  confirmAction,
  connectorVendorLabel,
  CONFIRM_BLOCKED,
  CONFIRM_PORTAL_NEXT,
  routeIsChoosable,
  safePortalHref,
  SEND_ACTION,
  SEND_CHOOSER_HEADING,
  SEND_NEEDS_CAPTURES,
  SEND_WITHOUT_CAPTURES,
  SEND_WITHOUT_CAPTURES_NOTE,
  sendRoutes,
  CONFIRM_FAILED,
  CONFIRM_HEADING,
  CONNECTOR_CHIP,
  DEVICES_FAILED,
  DRY_RUN_ACTION,
  DRY_RUN_CREATED_NOTHING,
  DRY_RUN_FAILED,
  DRY_RUN_RUNNING,
  DRY_RUN_SENTENCE,
  ESCALATE_FAILED,
  ESCALATE_RUNNING,
  MAX_PASTE_CHARS,
  NOT_ESCALATED_NOTE,
  NO_AUTHORED_PLAN_NOTE,
  NO_BUNDLE_YET,
  NO_CAPTURE_YET,
  NO_CASE_CONNECTOR,
  PASTE_INVITE,
  PLAN_FAILED,
  PLAN_LEGEND,
  PREPARE_FAILED,
  PREPARING_NOTE,
  REDACTION_SHORT,
  ROUTE_LABEL,
  ROW_RENDER_CAP,
  SECTION_ORDER,
  STATE_READ_FAILED,
  STATUS_CHIP,
  TEMPLATE_NEEDS_NAME,
  TICKET_DELIVERY_LABEL,
  TICKET_DELIVERY_ROUTE,
  UPLOAD_FAILED,
  UPLOAD_FORMATS_LINE,
  blockerLine,
  boundSteps,
  buildCaptureWrite,
  buildConfirmRequest,
  buildEscalateRequest,
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
  dryRunCallLine,
  dryRunElapsed,
  dryRunTone,
  evidenceLine,
  failedCommandLine,
  failedCommands,
  hasCapability,
  humanBytes,
  isCollecting,
  isMissingField,
  missingOutputs,
  missingOutputsLine,
  needsExistingCase,
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
  settingsHref,
  severityChoices,
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
  existing_case_number: string;
};

const EMPTY_FIELDS: CaseFields = {
  title: "", severity: "", product: "", serial_number: "",
  contract_id: "", contact_name: "", contact_email: "", existing_case_number: "",
};

/** What the ONE confirmation screen lets a person change. Everything else on it
 *  — the route, the bundle, the problem statement — is what the SERVER built and
 *  what the screen showed, and the server refuses an edit to any of it. */
const CONFIRM_FIELDS: { key: keyof CaseFields; label: string }[] = [
  { key: "title", label: "Title" },
  { key: "contact_name", label: "Contact name" },
  { key: "contact_email", label: "Contact email" },
  { key: "serial_number", label: "Serial number" },
  { key: "contract_id", label: "Contract" },
];

/** The fields of the prepared form the operator's edits start from. */
function fieldsFromForm(form: TacCaseForm): CaseFields {
  return {
    title: form.title ?? "",
    severity: form.severity ?? "",
    product: form.product ?? "",
    serial_number: form.serial_number ?? "",
    contract_id: form.contract_id ?? "",
    contact_name: form.contact_name ?? "",
    contact_email: form.contact_email ?? "",
    existing_case_number: form.existing_case_number ?? "",
  };
}

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

export default function TacEscalationPanel({ incidentId, autoStart = false, onCaseOpened }: {
  incidentId: string;
  /** Open the panel with the ONE ACTION already in flight. The investigation
   *  answer card presses Escalate and mounts this; asking the operator to press
   *  a second, identical button would be the extra click the whole feature
   *  exists to remove (owner, 2026-09-06). */
  autoStart?: boolean;
  /** The case this panel just opened, so the host's own answer card can carry
   *  the chip without re-reading it. */
  onCaseOpened?: (link: TacCaseLink) => void;
}) {
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
  // The "Send to vendor" chooser. Closed until the operator asks for it: the
  // step is ONE button, and the list of where it could go is the answer to
  // pressing it (owner, 2026-09-08).
  const [chooserOpen, setChooserOpen] = useState(false);

  // ── the ONE ACTION (internal/tac/escalate.go) ─────────────────────────────
  // Escalate → (the server classifies, plans, routes and collects) → prepare →
  // ONE confirmation screen → Open case. `route` is what the server chose and
  // WHY; `proposal` is exactly what will be sent, and nothing has been sent
  // while it is on screen.
  const [route, setRoute] = useState<TacEscalationRoute | null>(null);
  const [routeNote, setRouteNote] = useState("");
  const [escalating, setEscalating] = useState(false);
  const [escalateErr, setEscalateErr] = useState("");
  const [proposal, setProposal] = useState<TacProposal | null>(null);
  const [preparing, setPreparing] = useState(false);
  const [prepareErr, setPrepareErr] = useState("");
  const [confirmFields, setConfirmFields] = useState<CaseFields>(EMPTY_FIELDS);
  const [confirmErr, setConfirmErr] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [caseLink, setCaseLink] = useState<TacCaseLink | null>(null);
  // The confirm reply's own rendering of the chip. Kept beside the link so the
  // panel shows the SERVER's sentence rather than recomputing one.
  const [caseLineFromConfirm, setCaseLineFromConfirm] = useState("");
  const [caseTipFromConfirm, setCaseTipFromConfirm] = useState("");
  // The per-case upload credential a vendor's portal mints (Cisco CXD). It is
  // typed here, sent once and never stored or echoed back.
  //
  // There is no upload HOST control beside it on purpose. The client pins the
  // vendor's published upload host and refuses any other, so a box asking an
  // operator to name one could only produce a refusal.
  const [uploadToken, setUploadToken] = useState("");
  // The dry run (internal/tac/dryrun.go): authenticate for real, describe the
  // rest, create nothing. Secondary to Open case, always.
  const [dryRun, setDryRun] = useState<TacDryRunReport | null>(null);
  const [dryRunErr, setDryRunErr] = useState("");
  const [dryRunning, setDryRunning] = useState(false);

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

  /**
   * SEED FROM THE SERVER'S OWN STATE.
   *
   * The route, the confirmation screen and the opened case all live on the
   * escalation the api holds, and the panel is only one window onto it. Without
   * this, an operator who REFRESHED THE BROWSER mid-escalation — or who came
   * back to an incident a colleague escalated an hour ago — saw the captures and
   * nothing else: `route` is local state that only the escalate leg sets, so the
   * confirmation screen could never return and the auto-prepare effect below
   * could never fire.
   *
   * It seeds only what the panel does not already have, so a value this session
   * produced always wins over a re-read.
   */
  useEffect(() => {
    if (!state) return;
    if (!route && state.route) setRoute(state.route);
    if (!proposal && !prepareErr && state.proposal) {
      setProposal(state.proposal);
      // The editable half of the screen is seeded HERE too. Rendering a
      // confirmation screen whose device line says FTX2447ABCD while its serial
      // BOX is empty would be the worst of both: it looks pre-filled and submits
      // blank.
      setConfirmFields(fieldsFromForm(state.proposal.form));
    }
    if (!caseLink && info?.case) {
      setCaseLink(info.case);
      // The chip renders the SERVER's own two strings whenever it has them, and
      // the render below reads them from here once a link is in hand — so they
      // are seeded together with the link. Seeding one without the other would
      // hand the chip an empty sentence and let it fall back to the mirror for a
      // case the server had already worded.
      setCaseLineFromConfirm(info.case_status_line ?? "");
      setCaseTipFromConfirm(info.case_tooltip ?? "");
    }
  }, [state, route, proposal, prepareErr, caseLink, info?.case, info?.case_status_line, info?.case_tooltip]);

  // The escalation's state, and the caller's own inventory for the device picker.
  useEffect(() => {
    setInfo(null); setInfoErr(""); setClassify(null); setClassErr("");
    setDeviceId(""); setPlanErr(""); setCollectErr(""); setPasteIntent(""); setPasteText("");
    setSaved([]); setSavedErr(""); setUploaded(null); setUploadErr(""); setRefusals([]);
    setSelectedId(""); setExpanded({}); setSaveName(""); setSaveErr(""); setSaveNote("");
    setCaseForm(null); setCaseConnector(null); setCaseResult(null); setCaseErr("");
    setRoute(null); setRouteNote(""); setEscalateErr(""); setProposal(null); setPrepareErr("");
    setConfirmFields(EMPTY_FIELDS); setConfirmErr(""); setCaseLink(null);
    setCaseLineFromConfirm(""); setCaseTipFromConfirm("");
    setUploadToken("");
    setDryRun(null); setDryRunErr("");
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

  /**
   * THE ONE ACTION (owner, 2026-09-06: "open the case with one or two clicks").
   *
   * One press does the whole first half: it classifies (which is also what
   * gives the panel the class list an override picks from), then asks the
   * server to escalate — which plans, chooses the capture, decides the ROUTE
   * from the tenant's settings and starts collecting. Nothing leaves the
   * platform: neither call has a path to a vendor.
   *
   * The escalate leg is allowed to fail WITHOUT taking the classification with
   * it. A deployment that cannot route still classifies, still plans and still
   * builds the bundle, and the operator is told which half did not happen.
   */
  const runEscalate = async () => {
    setClassErr(""); setEscalateErr(""); setPrepareErr(""); setProposal(null);
    setClassifying(true); setEscalating(true);
    let classId = "";
    try {
      const c = await api.tacClassify(incidentId);
      if (!alive.current) return;
      setClassify(c);
      classId = c.classification?.class_id ?? "";
      setClassOverride(classId);
    } catch (e) {
      if (alive.current) { setClassErr(tacError(e, CLASSIFY_FAILED)); setEscalating(false); }
      return;
    } finally {
      if (alive.current) setClassifying(false);
    }
    const dev = (deviceId || info?.devices?.[0] || "").trim();
    try {
      if (dev) {
        const r = await api.tacEscalate(
          incidentId,
          buildEscalateRequest(dev, classId, includeOptional, target),
        );
        if (!alive.current) return;
        setRoute(r.route);
        setRouteNote(r.capture_note ?? "");
        if (!deviceId) setDeviceId(dev);
      }
      await readState();
    } catch (e) {
      if (alive.current) setEscalateErr(tacError(e, ESCALATE_FAILED));
    } finally {
      if (alive.current) setEscalating(false);
    }
  };

  /**
   * The step BETWEEN the two clicks, and it is not a click.
   *
   * Once the collection has finished the confirmation screen is built without
   * anybody pressing anything — the whole point of the one-action flow is that
   * the operator presses Escalate and then reads. Prepare still sends nothing:
   * it builds the redacted bundle and fills the form, and says whether Confirm
   * could succeed.
   */
  const runPrepare = useCallback(async (connectorId?: string) => {
    const dev = (deviceId || info?.devices?.[0] || "").trim();
    if (!dev) return;
    setPrepareErr(""); setPreparing(true);
    try {
      const r = await api.tacEscalatePrepare(
        incidentId,
        buildEscalateRequest(dev, classOverride || classification?.class_id || "", includeOptional, target, {
          connectorId: connectorId ?? "",
          severity: confirmFields.severity,
          title: confirmFields.title,
        }),
      );
      if (!alive.current) return;
      setProposal(r.proposal);
      setRoute(r.proposal.route);
      setConfirmFields(fieldsFromForm(r.proposal.form));
    } catch (e) {
      if (alive.current) setPrepareErr(tacError(e, PREPARE_FAILED));
    } finally {
      if (alive.current) setPreparing(false);
    }
    // `target` and the edited fields are applied when the screen is (re)built,
    // not on every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incidentId, deviceId, info?.devices, classOverride, classification?.class_id, includeOptional]);

  /**
   * CLICK TWO. The ONLY call in this panel that can cause a case to exist, and
   * it carries the operator's own edits — so filling a blocked field on the
   * screen works, and leaving it blank is still refused BY NAME.
   */
  const runConfirm = async () => {
    if (!proposal) return;
    setConfirmErr(""); setConfirming(true);
    try {
      const r = await api.tacEscalateConfirm(
        incidentId,
        buildConfirmRequest(confirmFields, { token: uploadToken }),
      );
      if (!alive.current) return;
      setCaseResult(r.result);
      setCaseLink(r.case);
      setCaseLineFromConfirm((r.status_line ?? "").trim());
      setCaseTipFromConfirm((r.tooltip ?? "").trim());
      onCaseOpened?.(r.case);
      setUploadToken("");
      await readState();
    } catch (e) {
      if (alive.current) setConfirmErr(tacError(e, CONFIRM_FAILED));
    } finally {
      if (alive.current) setConfirming(false);
    }
  };

  /**
   * The dry run. It authenticates against the configured endpoint with the
   * stored credential — a real, read-only call — and describes every other
   * request a submit would make, field by field, with the secrets already
   * redacted by the connector. It creates NOTHING, and the report says so.
   */
  const runDryRun = async () => {
    setDryRunErr(""); setDryRun(null); setDryRunning(true);
    try {
      const r = await api.tacEscalateDryRun(incidentId, route?.connector_id);
      if (alive.current) setDryRun(r.dry_run);
    } catch (e) {
      if (alive.current) setDryRunErr(tacError(e, DRY_RUN_FAILED));
    } finally {
      if (alive.current) setDryRunning(false);
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

  // The answer card presses Escalate and mounts this panel; pressing an
  // identical button again is the click the one-action flow exists to remove.
  // It fires ONCE per incident: `autoRan` is what stops a re-render restarting
  // an escalation that is already under way.
  const autoRan = useRef("");
  useEffect(() => {
    if (!autoStart || !info || autoRan.current === incidentId) return;
    if (state?.classification || classify) return;
    autoRan.current = incidentId;
    void runEscalate();
    // runEscalate is re-created on every render; the ref is the guard, not the
    // dependency list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoStart, info, incidentId, state?.classification, classify]);

  // The confirmation screen is built WITHOUT a second press: once the server has
  // stopped collecting and there is a capture to bundle, prepare runs on its
  // own. It still sends nothing — that is what makes this safe to do silently.
  useEffect(() => {
    if (!route || preparing || proposal || prepareErr || caseLink) return;
    if (running || !state?.capture) return;
    void runPrepare();
  }, [route, preparing, proposal, prepareErr, caseLink, running, state?.capture, runPrepare]);

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
      setCaseFields(fieldsFromForm(r.form));
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
      if (r.case) { setCaseLink(r.case); onCaseOpened?.(r.case); }
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
  // The connector the SERVER routed this case to. Its declared severity
  // vocabulary and its capabilities are what the confirmation screen renders —
  // the client never guesses either.
  const routedConnector = (info.connectors ?? []).find((c) => c.id === route?.connector_id);
  const routedVendorLabel = routedConnector ? connectorVendorLabel(routedConnector) : "";
  // The number the operator pastes back off a vendor's portal, checked against
  // the shape their administrator configured. Empty is fine — the case may not
  // be open yet — and anything else that is not a case number stops the button
  // rather than being filed on the incident.
  const portalNumberOK = !route?.portal ||
    caseNumberLooksValid(routedConnector?.case_number_pattern, confirmFields.existing_case_number);
  // What the operator has typed into the two boxes this screen owns. The
  // proposal was built before they reached the keyboard, so both are missing
  // on it by definition; a blocker naming one of them is cleared HERE.
  const suppliedOnScreen = {
    existingCaseNumber: confirmFields.existing_case_number,
    uploadToken,
  };
  // Which routes the "Send to vendor" chooser offers, and whether there is
  // anything to send yet.
  const deviceVendor = dialectVendor(plan?.dialect ?? capture?.dialect ?? "");
  const chooserRoutes = sendRoutes(info.connectors, deviceVendor, route?.connector_id ?? "");
  const captured = capturesHaveRun(state);
  // The case as it stands. What this panel just opened wins; otherwise the
  // state read carries it, so a reload still shows the number and its status.
  const shownCase = caseLink ?? info.case ?? null;

  return (
    <section className="tac-panel card" aria-label="Escalate to TAC">
      <div className="tac-head">
        <h2 className="tac-h">Escalate to TAC</h2>
        <span className="mini-meta tac-ver">Issue catalogue {info.catalog_version}</span>
      </div>

      {/* ── step 1: THE ONE ACTION ───────────────────────────────────────────
          One press classifies, plans, chooses the capture, decides the route
          and starts collecting. Nothing leaves the platform until the person
          presses Open case on the confirmation screen below. */}
      {!started && (
        <div className="tac-start">
          <p className="mini-meta">{info.state_note || NOT_ESCALATED_NOTE}</p>
          <button
            type="button"
            className="btn accent"
            onClick={() => { void runEscalate(); }}
            disabled={classifying || escalating}
            data-testid="tac-escalate"
          >
            {classifying || escalating ? ESCALATE_RUNNING : "Escalate to TAC"}
          </button>
          {classErr && <p className="tac-bad" role="alert">{classErr}</p>}
        </div>
      )}
      {escalateErr && <p className="tac-bad" role="alert" data-testid="tac-escalate-error">{escalateErr}</p>}

      {/* The route, and the server's own sentence saying WHY it was chosen. It
          is rendered as soon as the escalation exists, so the operator reads
          where this is going while the collection is still running. */}
      {route && !proposal && (
        <p className="fact-line" data-testid="tac-route">
          {ROUTE_LABEL}: <b>{route.display}</b> — {route.note}
        </p>
      )}
      {routeNote && <p className="fact-line" data-testid="tac-capture-note">{routeNote}</p>}

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

      {/* ── THE ONE CONFIRMATION SCREEN ──────────────────────────────────────
          Exactly what will be sent, and nothing has been sent. The route and
          the server's own sentence saying why it was chosen, the case title,
          the severity, the named human, the serial and model, the contract, the
          bundle and its size, Correlix's problem statement — and, immediately
          above the button, the two standing claims verbatim: the redaction
          promise and the approval sentence.

          §15 LLM02: every value here is remote- or model-authored text and is
          rendered as escaped React text. The problem statement is a read-only
          textarea for the same reason. */}
      {route && (
        <section className="tac-step" aria-labelledby="tac-confirm-h" data-testid="tac-confirm">
          <h3 id="tac-confirm-h" className="tac-step-h">{CONFIRM_HEADING}</h3>
          {prepareErr && <p className="tac-bad" role="alert" data-testid="tac-prepare-error">{prepareErr}</p>}
          {!proposal && !prepareErr && (
            <p className="fact-line" role="status" data-testid="tac-preparing">{PREPARING_NOTE}</p>
          )}

          {proposal && (
            <div className="tac-confirm">
              <p className="fact-line" data-testid="tac-confirm-route">
                {ROUTE_LABEL}: <b>{proposal.route.display}</b> — {proposal.route.note}
              </p>

              <div className="tac-form">
                <label className="tac-field">
                  <span>Title</span>
                  <input
                    type="text"
                    maxLength={200}
                    value={confirmFields.title}
                    data-testid="tac-confirm-title"
                    onChange={(e) => setConfirmFields((f) => ({ ...f, title: e.target.value }))}
                  />
                </label>
                <label className="tac-field">
                  <span>Severity</span>
                  {/* The vendor's own vocabulary when it publishes one; free text
                      when it does not. An empty list is a FACT about the vendor,
                      not a gap, so nothing is invented to fill the select. */}
                  {severityChoices(routedConnector).length > 0 ? (
                    <select
                      value={confirmFields.severity}
                      data-testid="tac-confirm-severity"
                      onChange={(e) => setConfirmFields((f) => ({ ...f, severity: e.target.value }))}
                    >
                      <option value="">Choose…</option>
                      {severityChoices(routedConnector).map((v) => (
                        <option key={v} value={v}>{v}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type="text"
                      maxLength={64}
                      value={confirmFields.severity}
                      data-testid="tac-confirm-severity"
                      onChange={(e) => setConfirmFields((f) => ({ ...f, severity: e.target.value }))}
                    />
                  )}
                </label>
                {CONFIRM_FIELDS.filter((f) => f.key !== "title").map(({ key, label }) => (
                  <label className="tac-field" key={key}>
                    <span>{label}</span>
                    <input
                      type="text"
                      maxLength={200}
                      value={confirmFields[key]}
                      data-testid={`tac-confirm-${key}`}
                      onChange={(e) => setConfirmFields((f) => ({ ...f, [key]: e.target.value }))}
                    />
                  </label>
                ))}
                {needsExistingCase(routedConnector, proposal) && (
                  <label className="tac-field">
                    <span>Case number</span>
                    <input
                      type="text"
                      maxLength={64}
                      value={confirmFields.existing_case_number}
                      data-testid="tac-confirm-existing-case"
                      onChange={(e) => setConfirmFields((f) => ({ ...f, existing_case_number: e.target.value }))}
                    />
                  </label>
                )}
                {/* THE UPLOAD TOKEN. A route that attaches to a case the vendor
                    already opened authenticates the upload with a per-case
                    credential the administrator copies out of the vendor's own
                    portal. The server names it as a blocker whenever it is
                    needed, so this box appears exactly where a case cannot be
                    filed without it and nowhere else.

                    It is a CREDENTIAL and it is treated as one: masked at the
                    keyboard, never pre-filled, sent once, and cleared the
                    moment the case is filed. Nothing stores it and nothing
                    reads it back. */}
                {needsUploadToken(proposal) && (
                  <label className="tac-field">
                    <span>{UPLOAD_TOKEN_LABEL}</span>
                    <input
                      type="password"
                      maxLength={512}
                      autoComplete="off"
                      spellCheck={false}
                      value={uploadToken}
                      data-testid="tac-confirm-upload-token"
                      onChange={(e) => setUploadToken(e.target.value)}
                    />
                    <span className="fact-line">{UPLOAD_TOKEN_HINT}</span>
                  </label>
                )}
                {/* THE NUMBER THAT COMES BACK. On a manual route the case is
                    created in the vendor's own portal, so this is the one value
                    Correlix cannot derive — and the one the next operator will
                    search for. It is optional (the case may not be open yet)
                    and checked against the shape the administrator configured
                    for this vendor, at the keyboard, before it is filed. */}
                {proposal.route.portal && !needsExistingCase(routedConnector, proposal) && (
                  <label className="tac-field">
                    <span>{CASE_NUMBER_LABEL}</span>
                    <input
                      type="text"
                      maxLength={64}
                      value={confirmFields.existing_case_number}
                      data-testid="tac-portal-case-number"
                      aria-invalid={!portalNumberOK}
                      onChange={(e) => setConfirmFields((f) => ({ ...f, existing_case_number: e.target.value }))}
                    />
                  </label>
                )}
              </div>

              <p className="fact-line" data-testid="tac-confirm-device">
                {proposal.form.product || "Model not stated"}
                {proposal.form.serial_number ? ` · ${proposal.form.serial_number}` : ""}
              </p>
              <p className="fact-line" data-testid="tac-confirm-bundle">
                {proposal.bundle.name} · {humanBytes(proposal.bundle.bytes)}
              </p>
              <label className="tac-field">
                <span>Problem statement</span>
                <textarea
                  className="tac-portal"
                  rows={8}
                  readOnly
                  data-testid="tac-confirm-statement"
                  value={proposal.form.description}
                />
              </label>

              {(proposal.warnings ?? []).length > 0 && (
                <ul className="tac-warnings" data-testid="tac-warnings">
                  {(proposal.warnings ?? []).slice(0, ROW_RENDER_CAP).map((w, i) => (
                    <li key={`warn-${i}`} className="fact-line">{w}</li>
                  ))}
                </ul>
              )}

              {unresolvedBlockers(proposal, suppliedOnScreen).length > 0 && (
                <ul className="tac-blockers" role="alert" data-testid="tac-blockers">
                  {unresolvedBlockers(proposal, suppliedOnScreen).slice(0, ROW_RENDER_CAP).map((b, i) => (
                    <li key={`blk-${b.key}-${i}`} data-testid={`tac-blocker-${b.key}`}>
                      {blockerLine(b)}{" "}
                      {settingsHref(b.settings_hint) ? (
                        <a className="tac-conn-link" href={settingsHref(b.settings_hint)}>{b.settings_hint}</a>
                      ) : (
                        <span className="fact-line">{b.settings_hint}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              {/* The two standing claims, verbatim, immediately above the button
                  that sends. They are the server's own strings: if either ever
                  stops being true it is deleted there, with the code that made
                  it false. */}
              <p className="fact-line" data-testid="tac-redaction-promise">{proposal.redaction}</p>
              <p className="fact-line" data-testid="tac-approval">{proposal.approval}</p>
              {/* A MANUAL route opens nothing, so the screen says what pressing
                  the button DOES before it is pressed. Without it, "Prepare for
                  the portal" is a button whose outcome you have to press to
                  learn (owner, 2026-09-08). */}
              {proposal.route.portal && (
                <p className="fact-line" data-testid="tac-portal-next">{CONFIRM_PORTAL_NEXT}</p>
              )}

              <div className="tac-actions">
                <button
                  type="button"
                  className="btn accent"
                  disabled={!confirmReady(proposal, suppliedOnScreen) || confirming || !portalNumberOK}
                  aria-disabled={!confirmReady(proposal, suppliedOnScreen) || !portalNumberOK}
                  data-testid="tac-confirm-btn"
                  onClick={() => { void runConfirm(); }}
                >
                  {confirmAction(proposal.route.portal, confirming)}
                </button>
                {/* SECONDARY, deliberately: Open case is what this screen is
                    for, and a dry run is what you do the day you bring
                    credentials rather than mid-incident. */}
                <button
                  type="button"
                  className="btn"
                  disabled={dryRunning}
                  data-testid="tac-dry-run-btn"
                  onClick={() => { void runDryRun(); }}
                >
                  {dryRunning ? DRY_RUN_RUNNING : DRY_RUN_ACTION}
                </button>
                {proposal.route.portal && (
                  <button
                    type="button"
                    className="btn"
                    data-testid="tac-confirm-copy"
                    onClick={() => {
                      void navigator.clipboard?.writeText(proposal.form.portal_text);
                      setCaseNote("The case text was copied.");
                    }}
                  >
                    Copy the case text
                  </button>
                )}
                {safePortalHref(proposal.form.portal_url) && (
                  <a
                    className="btn"
                    href={safePortalHref(proposal.form.portal_url)}
                    target="_blank"
                    rel="noreferrer noopener"
                    data-testid="tac-confirm-portal-link"
                  >
                    Open the vendor portal
                  </a>
                )}
              </div>
              {!proposal.ready && (
                <p className="tac-bad" role="status" data-testid="tac-confirm-blocked">
                  {proposal.blocker_note || CONFIRM_BLOCKED}
                </p>
              )}
              {!portalNumberOK && (
                <p className="tac-bad" role="alert" data-testid="tac-case-number-bad">
                  {caseNumberRefusal(routedVendorLabel)}
                </p>
              )}
              {confirmErr && <p className="tac-bad" role="alert" data-testid="tac-confirm-error">{confirmErr}</p>}
              {dryRunErr && <p className="tac-bad" role="alert" data-testid="tac-dry-run-error">{dryRunErr}</p>}
              {dryRun && <DryRunReport report={dryRun} />}
            </div>
          )}

          {/* The case comes BACK to the incident: the number, the vendor's own
              status, and how often it refreshes. A failed read renders "status
              unknown since …", never the status it last saw. */}
          {shownCase && (
            <TacCaseChip
              link={shownCase}
              incidentId={incidentId}
              onRefreshed={setCaseLink}
              statusLine={caseLink ? caseLineFromConfirm : info.case_status_line}
              tooltip={caseLink ? caseTipFromConfirm : info.case_tooltip}
            />
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
              {/* ONE BUTTON, THEN A CHOOSER (owner, 2026-09-08: "when they are
                  ready with captures, they should hit a button, it will let
                  them choose the vendor and send").

                  Before the captures have run it is disabled and says why in
                  one line — with the honest escape beside it, because some
                  vendors do accept a case with a description and no outputs and
                  an operator who knows that must not be blocked by us. */}
              <div className="tac-actions" data-testid="tac-send">
                <button
                  type="button"
                  className="btn accent"
                  disabled={!captured || preparing || chooserRoutes.length === 0}
                  aria-disabled={!captured}
                  aria-expanded={chooserOpen}
                  data-testid="tac-send-btn"
                  onClick={() => setChooserOpen((v) => !v)}
                >
                  {SEND_ACTION}
                </button>
                {!captured && (
                  <span className="mini-meta" data-testid="tac-send-blocked">{SEND_NEEDS_CAPTURES}</span>
                )}
              </div>
              {!captured && (
                <details className="tac-fold" data-testid="tac-send-anyway">
                  <summary>{SEND_WITHOUT_CAPTURES}</summary>
                  <p className="fact-line">{SEND_WITHOUT_CAPTURES_NOTE}</p>
                  <button
                    type="button"
                    className="btn"
                    disabled={preparing || chooserRoutes.length === 0}
                    data-testid="tac-send-anyway-btn"
                    onClick={() => setChooserOpen(true)}
                  >
                    {SEND_ACTION}
                  </button>
                </details>
              )}

              {chooserOpen && chooserRoutes.length > 0 && (
                <div className="tac-chooser" data-testid="tac-vendor-chooser">
                  <h4 className="tac-section-h">{SEND_CHOOSER_HEADING}</h4>
                  <ul className="tac-connectors">
                    {chooserRoutes.map((c) => (
                      <ChooserRow
                        key={c.id}
                        info={c}
                        busy={preparing}
                        onChoose={() => {
                          setChooserOpen(false);
                          setProposal(null);
                          setPrepareErr("");
                          void runPrepare(c.id);
                        }}
                      />
                    ))}
                  </ul>
                </div>
              )}

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
                {safePortalHref(caseForm.portal_url) && (
                  <a
                    className="btn"
                    href={safePortalHref(caseForm.portal_url)}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
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
  const usable = state === "ready" || state === "attach-only" || state === "manual-configured";
  // A MANUAL path with no details brought is in exactly the state an
  // unconfigured API connector is in — a real option, not yet usable — so it
  // gets the same next step: the link to where the details are brought (owner,
  // 2026-09-08). Its chip still says Manual, because configuration can bring a
  // portal address and can never bring an API.
  const needsSetup = state === "not-configured" || state === "manual";
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
      {needsSetup && (
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

/**
 * One row of the "Send to vendor" chooser: where this case would go, what
 * happens if it goes there, and its chip.
 *
 * It is deliberately NOT the connector row. The connector rows are a catalogue
 * — every path this device could ever use, with its research behind an (i) — and
 * this is a decision the operator makes once, mid-incident, from the two or
 * three routes that are actually live. A path that cannot be chosen is still
 * SHOWN, greyed, with the link to where its details are brought: an option
 * missing from a chooser is indistinguishable from an option that does not
 * exist (§ the same honesty rule the Tier-3 connectors exist for).
 */
function ChooserRow({ info, busy, onChoose }: {
  info: TacConnectorInfo;
  busy: boolean;
  onChoose: () => void;
}) {
  const state = connectorState(info);
  const choosable = routeIsChoosable(info);
  return (
    <li className={`tac-conn${choosable ? "" : " off"}`} data-testid={`tac-route-${info.id}`}>
      <button
        type="button"
        className="btn"
        disabled={!choosable || busy}
        aria-disabled={!choosable}
        onClick={onChoose}
      >
        {info.display}
      </button>
      <span className="mini-meta">{connectorCapabilityLine(info)}</span>
      <span className={`tac-chip tac-chip-${state}`}>{CONNECTOR_CHIP[state]}</span>
      {!choosable && (
        <a
          className="mini-meta tac-conn-link"
          href={TICKET_DELIVERY_ROUTE}
          title={connectorStatusNote(info)}
        >
          {TICKET_DELIVERY_LABEL}
        </a>
      )}
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

/**
 * The dry run's report (internal/tac/dryrun.go).
 *
 * The outcome and the server's own note first, because that is the answer. Then
 * the call sequence as a COLLAPSED list — an operator checking a staging host
 * against their onboarding paperwork expands one row; everybody else reads the
 * outcome and stops. Each row expands to the field table: what Correlix calls
 * the field, what the vendor calls it where the tenant's onboarding bound a
 * name, and the value that would be sent.
 *
 * A `secret` field renders its `value` AS-IS: the connector already redacted it
 * before it crossed the wire, and re-masking a mask would only hide whether the
 * redaction happened. It is marked so nobody reads the mark as the value.
 *
 * "Nothing was created" is the SERVER'S claim (`created_nothing`), rendered
 * rather than asserted here — a client that decided it for itself would be
 * vouching for code it cannot see.
 */
function DryRunReport({ report }: { report: TacDryRunReport }) {
  const elapsed = dryRunElapsed(report);
  return (
    <div className="tac-dryrun" data-testid="tac-dry-run">
      <p className="fact-line">
        <span className={`tac-chip ${dryRunTone(report.outcome)}`} data-testid="tac-dry-run-outcome">
          {report.outcome}
        </span>{" "}
        {DRY_RUN_SENTENCE[report.outcome]} {report.note}
      </p>
      <p className="fact-line" data-testid="tac-dry-run-created-nothing">
        {report.created_nothing ? DRY_RUN_CREATED_NOTHING : ""}
        {report.auth_mode ? ` ${report.auth_mode}` : ""}
        {elapsed ? ` · ${elapsed}` : ""}
        {report.limits ? ` · ${report.limits}` : ""}
      </p>
      {(report.blockers ?? []).length > 0 && (
        <ul className="tac-blockers" role="alert" data-testid="tac-dry-run-blockers">
          {(report.blockers ?? []).slice(0, ROW_RENDER_CAP).map((b, i) => (
            <li key={`drb-${b.key}-${i}`}>
              {blockerLine(b)}{" "}
              {settingsHref(b.settings_hint) ? (
                <a className="tac-conn-link" href={settingsHref(b.settings_hint)}>{b.settings_hint}</a>
              ) : (
                <span className="fact-line">{b.settings_hint}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      <ul className="tac-dryrun-calls" data-testid="tac-dry-run-calls">
        {(report.calls ?? []).slice(0, ROW_RENDER_CAP).map((c, i) => (
          <li key={`drc-${i}`}>
            <DryRunCallRow call={c} />
          </li>
        ))}
      </ul>
    </div>
  );
}

/** One call, collapsed. Nothing expands by default. */
function DryRunCallRow({ call }: { call: TacDryRunCall }) {
  return (
    <details className="tac-fold">
      <summary>{dryRunCallLine(call)}</summary>
      {call.note && <p className="fact-line">{call.note}</p>}
      {(call.fields ?? []).length > 0 && (
        <table className="tac-dryrun-fields">
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Vendor</th>
              <th scope="col">Value</th>
            </tr>
          </thead>
          <tbody>
            {(call.fields ?? []).slice(0, ROW_RENDER_CAP).map((f, i) => (
              <tr key={`drf-${f.name}-${i}`} title={f.note}>
                <td><code className="tac-id">{f.name}</code></td>
                <td>{f.vendor_name ?? ""}</td>
                <td>
                  {f.value}
                  {f.secret && <span className="tac-chip tac-chip-queued">redacted</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </details>
  );
}
