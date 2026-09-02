// notifyValidation.ts — client-side mirrors of the notification-channel
// validators the API enforces (src/backend/notify/channel_config.go:
// ValidateWebhookURL / ValidateAWSRegion / ValidateSNSTopicARN / ValidateE164 /
// ValidateTeamsConfig / ValidateSNSConfig).
//
// These are a UX affordance ONLY. The server is the authority and re-validates
// every PUT — nothing here may be treated as a security control (CLAUDE.md §3:
// the boundary that matters is the one on the other side of the wire). Their
// job is to say WHICH field is wrong, inline, before a round trip turns the
// same rule into an opaque 400.
//
// Keep the grammars byte-identical to the Go regexps; a client rule that is
// LOOSER than the server's only produces a confusing 400, but one that is
// TIGHTER blocks a config the platform would happily accept.

/** Field name → message. Empty object = valid. */
export type FieldErrors = Record<string, string>;

// awsRegionRe / snsTopicNameRe / awsAccountRe are transcriptions of the Go
// regexps. The region grammar is strict on purpose: the server interpolates the
// region into the SNS endpoint host.
const awsRegionRe = /^[a-z]{2,}(-[a-z0-9]+)+$/;
const snsTopicNameRe = /^[A-Za-z0-9_-]{1,256}(\.fifo)?$/;
const awsAccountRe = /^[0-9]{12}$/;
const e164Re = /^\+[1-9][0-9]{6,14}$/;

/**
 * validateWebhookUrl mirrors ValidateWebhookURL: https only (the URL carries a
 * bearer secret), a host, and no userinfo. Empty is valid — that is how a
 * channel is left unconfigured, and how a PUT preserves the stored secret.
 */
export function validateWebhookUrl(raw: string): string | null {
  const v = raw.trim();
  if (v === "") return null;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return "Webhook URL is not a valid URL.";
  }
  if (u.protocol.toLowerCase() !== "https:") {
    return "Webhook URL must use https — it carries a bearer secret, and http would send it in clear text.";
  }
  if (!u.host) return "Webhook URL must include a host.";
  if (u.username || u.password) return "Webhook URL must not embed credentials in the URL userinfo.";
  return null;
}

/** validateAwsRegion mirrors ValidateAWSRegion. Empty is valid (derived from the ARN). */
export function validateAwsRegion(region: string): string | null {
  const v = region.trim();
  if (v === "") return null;
  if (!awsRegionRe.test(v)) return `Region "${v}" is not a valid AWS region (expected e.g. us-east-1).`;
  return null;
}

/**
 * validateSnsTopicArn mirrors ValidateSNSTopicARN:
 * arn:<partition>:sns:<region>:<12-digit account>:<topic>. Empty is valid — an
 * SNS channel may target phone numbers only.
 */
export function validateSnsTopicArn(arn: string): string | null {
  const v = arn.trim();
  if (v === "") return null;
  const parts = v.split(":");
  if (parts.length !== 6) return "Topic ARN must look like arn:aws:sns:<region>:<account-id>:<topic>.";
  if (parts[0] !== "arn") return 'Topic ARN must start with "arn:".';
  if (!["aws", "aws-cn", "aws-us-gov"].includes(parts[1])) return `Topic ARN partition "${parts[1]}" is not an AWS partition.`;
  if (parts[2] !== "sns") return `Topic ARN service must be "sns", got "${parts[2]}".`;
  if (!awsRegionRe.test(parts[3])) return `Topic ARN region "${parts[3]}" is not a valid AWS region.`;
  if (!awsAccountRe.test(parts[4])) return "Topic ARN account id must be 12 digits.";
  if (!snsTopicNameRe.test(parts[5])) return "Topic ARN topic name contains characters SNS does not allow.";
  return null;
}

/** snsRegionFromArn mirrors SNSRegionFromARN ("" when the ARN is empty or malformed). */
export function snsRegionFromArn(arn: string): string {
  const parts = arn.trim().split(":");
  if (parts.length !== 6 || parts[0] !== "arn" || parts[2] !== "sns") return "";
  return parts[3];
}

/** splitList mirrors SplitList — comma-separated, blanks dropped. */
export function splitList(csv: string): string[] {
  return csv.split(",").map((s) => s.trim()).filter(Boolean);
}

/** validateE164 mirrors ValidateE164. */
export function validateE164(n: string): string | null {
  if (!e164Re.test(n.trim())) return `Phone number "${n.trim()}" is not E.164 (expected e.g. +14155550123).`;
  return null;
}

/**
 * teamsErrors mirrors ValidateTeamsConfig against the EFFECTIVE webhook — the
 * one being typed, or, when the field is untouched, the one the server already
 * holds (`webhookSet`). That is the same substitution handleTeamsConfig does,
 * so "enabled with no webhook anywhere" is caught here rather than as a 400.
 */
export function teamsErrors(input: { enabled: boolean; webhookSet: boolean; typedWebhook: string }): FieldErrors {
  const errs: FieldErrors = {};
  const urlErr = validateWebhookUrl(input.typedWebhook);
  if (urlErr) errs.webhook_url = urlErr;
  const haveWebhook = input.typedWebhook.trim() !== "" || input.webhookSet;
  if (input.enabled && !haveWebhook && !urlErr) {
    errs.webhook_url = "Configure a webhook URL before enabling Teams.";
  }
  return errs;
}

/** snsErrors mirrors ValidateSNSConfig field by field. */
export function snsErrors(cfg: {
  enabled: boolean;
  topic_arn: string;
  region: string;
  phone_numbers: string;
  scope: string;
}): FieldErrors {
  const errs: FieldErrors = {};
  const regionErr = validateAwsRegion(cfg.region);
  if (regionErr) errs.region = regionErr;
  const arnErr = validateSnsTopicArn(cfg.topic_arn);
  if (arnErr) errs.topic_arn = arnErr;

  const arnRegion = snsRegionFromArn(cfg.topic_arn);
  if (!arnErr && !regionErr && arnRegion !== "" && cfg.region.trim() !== "" && arnRegion !== cfg.region.trim()) {
    errs.region = `Region "${cfg.region.trim()}" does not match the topic ARN's region "${arnRegion}".`;
  }

  for (const n of splitList(cfg.phone_numbers)) {
    const e = validateE164(n);
    if (e) {
      errs.phone_numbers = e;
      break;
    }
  }

  if (cfg.enabled) {
    if (cfg.topic_arn.trim() === "" && splitList(cfg.phone_numbers).length === 0) {
      errs.topic_arn = "Configure a topic ARN or at least one phone number before enabling SNS.";
    } else if (cfg.region.trim() === "" && arnRegion === "") {
      errs.region = "Region is required when SNS is enabled without a topic ARN to derive it from.";
    }
  }

  if (!["", "all", "platform"].includes(cfg.scope.trim().toLowerCase())) {
    errs.scope = 'Scope must be "all" or "platform".';
  }
  return errs;
}

/** hasErrors is the save-button guard. */
export function hasErrors(e: FieldErrors): boolean {
  return Object.keys(e).length > 0;
}
