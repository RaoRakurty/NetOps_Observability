---
title: Pricing
sidebar_label: Pricing
description: The launch price of every Correlix tier, the unit each one is charged on, and the minimum commitment each carries.
page_type: reference
sidebar_position: 6
---

# Pricing

Correlix is priced on the **monitored device**. A device consumes one entitlement when at least one supported monitoring or collector configuration is enabled for it. Discovery is unlimited and free in every tier, and a device sitting in the inventory without active monitoring costs nothing. Several telemetry methods on one device are still one monitored device.

:::note These are launch prices, and they will be reviewed
The figures below are the prices Correlix enters the market with, approved on 5 September 2026. They are market-entry hypotheses rather than fixed terms. Correlix reviews them once real conversion data from design partners and paying customers exists, so a figure here can change for a future order. A price already written into a signed order form is unaffected by a later review.
:::

## Tiers

| Tier | Price | Monitored devices | Minimum commitment | How to buy |
|---|---|---|---|---|
| Community | $0, permanently | 25 | None | Download and run. No card, no expiry, no activation server |
| Team (starter pack) | $249 per month | Up to 50 included | The starter pack | Self-serve |
| Team (above the starter pack) | approximately $4 per monitored device per month | 51 to 250 | The starter pack | Self-serve |
| Enterprise | approximately $6 to $9 per monitored device per month | Contracted capacity | approximately $18,000 to $30,000 annual recurring revenue | Sales-assisted, contracted |
| Enterprise MSP | approximately $3 to $6 per pooled monitored device per month | Pooled across the managed tenants | approximately $24,000 annual recurring revenue and up | Sales-assisted, contracted |

The Enterprise and MSP figures are ranges because those tiers are contracted rather than listed. The range is the band a quote is drawn from, and the order form carries the number that applies to one customer.

## Community

Community is free permanently, not a trial that lapses into something smaller. It has no expiry date, needs no licence file, and reports nothing to Correlix.

| Fact | Value |
|---|---|
| Price | $0, permanently |
| Monitored devices | 25, enforced as a hard limit. The 26th activation is refused |
| Discovery | Unlimited. Discovery does not consume the monitoring allowance |
| Correlation, RCA, topology, protocol diagnostics | Included in full |
| Tenant isolation, permissions, sign-in | Included in full, in every tier |

## Team

The starter pack is one price for the first 50 monitored devices, so a team that grows from 12 devices to 40 pays the same. Above 50, each additional monitored device is charged at the per-device rate, up to the Team ceiling of 250.

The monitored-device allowance on Team does not block. Enabling monitoring past the purchased count succeeds, the excess is recorded, and the Licence page shows it. The overage is settled as a true-up with the account team. Correlix refuses no device during an incident because of a number on an order form.

## Enterprise and Enterprise MSP

Both tiers are contracted. Capacity, the per-device rate inside the band and the term are set in the order form rather than by the product.

Enterprise MSP pools the monitored devices across the tenants a provider manages, so one pooled entitlement covers the whole managed fleet. The tenant count is a broad plan ceiling and never a per-tenant charge. Tenant isolation is core in every tier and is never sold as an MSP capability.

## What the price is recorded in, and what it is not

A price lives in the order form and in the contract. It is never written into the product.

A Correlix licence file carries five things: the entitled features, the ceilings, the customer, the expiry with its grace period, and the support entitlement. It carries no price, no currency and no tier cost. A signed usage report carries meter counts and no monetary value either, so a report can be handed to anybody without disclosing commercial terms.

That separation is checked mechanically. `TestNoPriceLiteralsInLicenceCode` in `src/backend/internal/entitlement` scans the entitlement package, the licence package and the `correlix-licence` command for currency and price literals, and fails the build on any of them.

## Related

- [Licensing](/reference/licensing) for which parts of Correlix are Apache-2.0 and which are commercial add-ons.
- [Apply a licence](/administration/licence) for the ceilings a licence file carries and how to read usage against them.
- [Optional modules](/deploy/optional-modules) for the capabilities a commercial tier adds.
