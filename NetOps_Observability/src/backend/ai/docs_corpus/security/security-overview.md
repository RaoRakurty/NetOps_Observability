---
title: Read the Security Overview
sidebar_label: Security Overview
description: Read the Security Overview page from the top down, how much of the estate was assessed, the exposure pipeline, the flagship exposure story and exposure by seam.
page_type: task
sidebar_position: 2
---

# Read the Security Overview

**Security → Security Overview** is the first page of the Security section. It
answers four questions in order: how much of the estate was actually assessed,
what the exposure pipeline is doing, which correlated exposure matters most
right now, and where the estate meets untrusted networks. Every number on it
is a current verdict, not history.

## Before you begin

- `infrastructure:read`. The page is per tenant: every count and row is your own
  tenant's.
- At least one assessment. Until the security lane has run, the page says
  **No assessment has run yet.** To start one, see
  [Run a security scan](/security/run-a-scan).

## Steps

1. Go to **Security → Security Overview**.
2. Read **Exposure pipeline** first. **Assessment coverage** is the share of
   the estate that was assessed, with the number never assessed beneath it.
   A device that was never assessed is unknown, not clean.
3. Read the funnel beside it: **Scope**, **Discover**, **Prioritize**,
   **Validate** and **Mobilize**. See
   [Continuous threat and exposure management](/security/ctem) for what each
   stage counts.
4. Read the line under the funnel for the time and scan id of the last
   assessment, and the **Security lane** panel for whether the scanner is
   running and whether its results reached the engine.
5. Read **Exposure story**. It shows the flagship story: its causality chain,
   the owning seam, the verdict and the confidence. Select **Open the full
   story** to open it on **Security → Exposure Stories**.
6. Read **Evidence by class** and **Exposure by seam**, then **Verdict trend**.

## What you see

| Group | What it shows |
|---|---|
| **Exposure pipeline** | **Assessment coverage**, the five-stage funnel, the last assessment and the **Security lane** status. |
| **Exposure story** | The top correlated exposure, or **No story grounded yet.** |
| **Evidence by class** | Three lanes, **Hardening & posture**, **Seam exposure** and **Threat detections**, each with its count of current verdicts and the newest findings. **Standards coverage** counts findings tagged to each standard. |
| **Exposure by seam** | Findings per seam. An unassessed seam shows `—`. **Seam groups** lists which seams carry the same traffic as a redundant pair. |
| **Verdict trend** | **Verdicts per day**: **Fail**, **Warning**, **Pass** and **Total**, then the number of current findings across the scored seams. |

A lane that reads **None in the newest findings on this page — open the lane
to see them.** has verdicts, and they are older than the first page of
findings the overview reads. **No verdicts yet.** means the lane has none.

## Common questions

**Coverage is 40%. Are the other 60% of devices safe?** No. They were not
assessed, so nothing is known about them. Close the gap before you read the
verdicts as a picture of the estate.

**Why is Validate zero?** Correlix does not measure validation: no finding
carries a validation marker, so any other number would be invented. Read `0`
as not measured. See
[Continuous threat and exposure management](/security/ctem).

**Can I confirm a proposed seam group here?** Yes, with
`infrastructure:write`. Without it, the control is not shown.

## Related

- [Continuous threat and exposure management](/security/ctem)
- [Review exposures](/security/exposures)
- [Exposure stories](/security/exposure-stories)
- [Run a security scan](/security/run-a-scan)
