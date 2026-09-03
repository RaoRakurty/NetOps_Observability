---
title: Keep sites and inventory in sync
description: Enable the bundled inventory or point at an external one, choose a sync direction, run a sync or a push, and read the status lines that prove it worked.
page_type: task
sidebar_position: 2
---

# Keep sites and inventory in sync

**Infrastructure → Source of Truth** manages the inventory connector: the bundled inventory service that ships with the platform, or an external instance you already run. The connector exchanges device records. It never becomes the authority over what Correlix monitors.

The ongoing connection is what follows. Declaring sites and placing devices is [Place devices on the map](/infrastructure/geomap), and the one-off file seed is [Import inventory from a source of truth](/automation/import-and-sync).

## Before you begin

- Platform-owner access. The leaf is shown to the platform owner only, and the backend enforces the boundary independently.
- For an external instance, its base URL and an API token with read access to the device inventory.
- A decision on direction. Nothing moves until you pick one.

## Steps

### Step 1 - Read the current state

Open **Infrastructure → Source of Truth**. The status badge reads one of four values:

| Badge | What it means |
|---|---|
| **Connected** | Enabled, and either bundled or configured with a URL and a token. |
| **Bundled · off** | The bundled inventory exists but is not enabled. |
| **Disabled** | A URL or a token is configured, and the connector is off. |
| **Not set up** | Nothing is configured. |

### Step 2 - Set up the connection

1. Select **Set up**, or **Manage** where a connection already exists.
2. The wizard opens with the bundled inventory preselected. It ships wired, with no URL or token to paste. To use your own system instead, choose the external path and complete two more steps:
   - **Connect**: the inventory base URL.
   - **Authenticate**: an API token with read access. It is stored encrypted and never shown again.
3. Enable inventory discovery and set the **Poll interval (seconds)**. The minimum is 15 and the default is 60.

### Step 3 - Choose the sync direction

The direction decides what crosses, and **Off** is the default.

| Direction | What crosses |
|---|---|
| **Off** | Nothing. The record stays browsable, discovery neither populates it nor reads from it. Choose this when an external system will sync through its own API. |
| **Devices → Source of Truth** | One way, upward. Devices found by discovery are written into the record. Nothing is read back, so nothing is duplicated. Choose this to build the record from scratch. |
| **Source of Truth → Devices** | One way, downward. Externally declared devices are pulled in and appear under **Infrastructure → Devices** beside discovered ones, as additional records rather than as the authority over them. |
| **Bidirectional** | Both, with records de-duplicated by address, serial and name. |

Select **Save**. The confirmation states when it takes effect: `Saved. The collector picks up changes on its next poll.`

### Step 4 - Force a cycle

Two on-demand controls sit in the toolbar, and they are different operations:

- **Sync devices** pulls inventory records into **Infrastructure → Devices** now.
- **Push devices** pushes discovered devices out to the record now. It appears only when the direction includes writing, and it also runs on its own every 5 minutes after a 90-second first delay that lets discovery complete a cycle.

## Result

The badge reads **Connected**, and the two status lines under the toolbar carry the evidence.

The poll line reads `Last sync: <timestamp> · N device(s)`, and where the last poll failed the same line appends `· error: <message>`. A poll that has never run shows a dash for the timestamp rather than a zero-time.

The push line reads `Last push: <timestamp> · N added · M already present`, or `Last push: not run yet` before the first run, with `· error: <message>` appended on failure.

Where the direction includes a pull, the pulled devices appear in **Infrastructure → Devices** with the connector as their source, and the drift checks under **Security → Compliance** begin comparing the declared record against the observed one: registration, name, management address, serial and platform.

With the bundled inventory enabled, its console is embedded on the page with **Reload** and **Full screen** controls. An external instance is managed in its own console, and Correlix only exchanges records with it.

## Related

- [Import inventory from a source of truth](/automation/import-and-sync) for the one-way file seed.
- [Work with the device inventory](/infrastructure/devices) for where pulled records land.
- [Configuration drift](/security/config-drift) for drift in device configuration rather than in inventory records.
