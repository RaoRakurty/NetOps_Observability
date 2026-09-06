// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Unit cover for the client-side mirrors of the API's channel validators.
// These exist to keep the two implementations in step: each case here is a case
// the Go validator (src/backend/notify/channel_config.go) also rejects/accepts,
// so a drift shows up as a failing assertion rather than as a surprise 400.
import { describe, it, expect } from "vitest";
import {
  validateWebhookUrl, validateAwsRegion, validateSnsTopicArn, snsRegionFromArn,
  splitList, validateE164, teamsErrors, snsErrors, hasErrors,
} from "./notifyValidation";

const ARN = "arn:aws:sns:us-east-1:123456789012:netops-alerts";

describe("validateWebhookUrl", () => {
  it("accepts https and treats empty as unconfigured", () => {
    expect(validateWebhookUrl("https://x.webhook.office.com/webhookb2/abc")).toBeNull();
    expect(validateWebhookUrl("")).toBeNull();
    expect(validateWebhookUrl("   ")).toBeNull();
  });
  it("refuses http, a missing host and embedded userinfo", () => {
    expect(validateWebhookUrl("http://x.webhook.office.com/hook")).toMatch(/https/);
    expect(validateWebhookUrl("not a url")).toMatch(/valid URL/);
    expect(validateWebhookUrl("https://user:pw@x.webhook.office.com/hook")).toMatch(/userinfo/);
  });
});

describe("validateAwsRegion", () => {
  it("accepts the real region grammar", () => {
    for (const r of ["us-east-1", "eu-west-2", "us-gov-west-1", "cn-north-1"]) {
      expect(validateAwsRegion(r)).toBeNull();
    }
    expect(validateAwsRegion("")).toBeNull();
  });
  it("refuses anything that could redirect the signed endpoint host", () => {
    for (const r of ["us_east_1", "evil.example.com", "us-east-1/x", "US-EAST-1", "useast1"]) {
      expect(validateAwsRegion(r)).toMatch(/not a valid AWS region/);
    }
  });
});

describe("validateSnsTopicArn", () => {
  it("accepts a well-formed ARN (and FIFO topics) and treats empty as optional", () => {
    expect(validateSnsTopicArn(ARN)).toBeNull();
    expect(validateSnsTopicArn("arn:aws-us-gov:sns:us-gov-west-1:123456789012:t.fifo")).toBeNull();
    expect(validateSnsTopicArn("")).toBeNull();
  });
  it("names the broken field for each malformed shape", () => {
    expect(validateSnsTopicArn("arn:aws:sns:us-east-1:123456789012")).toMatch(/arn:aws:sns/);
    expect(validateSnsTopicArn("urn:aws:sns:us-east-1:123456789012:t")).toMatch(/start with/);
    expect(validateSnsTopicArn("arn:gcp:sns:us-east-1:123456789012:t")).toMatch(/partition/);
    expect(validateSnsTopicArn("arn:aws:sqs:us-east-1:123456789012:t")).toMatch(/service must be/);
    expect(validateSnsTopicArn("arn:aws:sns:nowhere:123456789012:t")).toMatch(/region/);
    expect(validateSnsTopicArn("arn:aws:sns:us-east-1:12345:t")).toMatch(/12 digits/);
    expect(validateSnsTopicArn("arn:aws:sns:us-east-1:123456789012:bad topic!")).toMatch(/does not allow/);
  });
});

describe("snsRegionFromArn / splitList / validateE164", () => {
  it("extracts the region only from a well-formed ARN", () => {
    expect(snsRegionFromArn(ARN)).toBe("us-east-1");
    expect(snsRegionFromArn("garbage")).toBe("");
  });
  it("splits an operator list dropping blanks", () => {
    expect(splitList(" +1, ,+2 ,")).toEqual(["+1", "+2"]);
    expect(splitList("")).toEqual([]);
  });
  it("enforces E.164", () => {
    expect(validateE164("+14155550123")).toBeNull();
    expect(validateE164("4155550123")).toMatch(/E.164/);
  });
});

describe("teamsErrors", () => {
  it("is clean when a stored webhook backs an enabled channel", () => {
    expect(teamsErrors({ enabled: true, webhookSet: true, typedWebhook: "" })).toEqual({});
  });
  it("refuses enabling with no webhook anywhere", () => {
    const e = teamsErrors({ enabled: true, webhookSet: false, typedWebhook: "" });
    expect(e.webhook_url).toMatch(/before enabling Teams/);
    expect(hasErrors(e)).toBe(true);
  });
  it("reports a plaintext webhook on the field", () => {
    expect(teamsErrors({ enabled: false, webhookSet: false, typedWebhook: "http://a/b" }).webhook_url).toMatch(/https/);
  });
});

describe("snsErrors", () => {
  const base = { enabled: false, topic_arn: "", region: "", phone_numbers: "", scope: "all" };
  it("is clean for a topic-only enabled channel", () => {
    expect(snsErrors({ ...base, enabled: true, topic_arn: ARN })).toEqual({});
  });
  it("reports a region that disagrees with the ARN", () => {
    expect(snsErrors({ ...base, topic_arn: ARN, region: "eu-west-1" }).region).toMatch(/does not match/);
  });
  it("refuses enabling with nowhere to send, and with no derivable region", () => {
    expect(snsErrors({ ...base, enabled: true }).topic_arn).toMatch(/topic ARN or at least one phone number/);
    expect(snsErrors({ ...base, enabled: true, phone_numbers: "+14155550123" }).region).toMatch(/Region is required/);
  });
  it("reports the first non-E.164 phone number and an illegal scope", () => {
    expect(snsErrors({ ...base, phone_numbers: "+14155550123, 555" }).phone_numbers).toMatch(/E.164/);
    expect(snsErrors({ ...base, scope: "everyone" }).scope).toMatch(/"all" or "platform"/);
  });
});
