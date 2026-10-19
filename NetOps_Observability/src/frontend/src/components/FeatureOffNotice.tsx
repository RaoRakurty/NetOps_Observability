// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// FeatureOffNotice — what a panel says when the feature behind it is switched
// off (owner 2026-10-18: point at where to turn it on, never at an environment
// variable — customers never edit the environment). Features are switched on
// the platform's Features page, which only a platform administrator can open,
// so ONE sentence serves every reader: it names the page and who can use it.
// No link: for anyone but a platform administrator it would land on nothing.

export function featureOffTip(feature: string): string {
  return `${feature} is off. A platform administrator can turn it on in Platform › Features.`;
}

export default function FeatureOffNotice({ feature, purpose }: {
  /** The switch's label on the Features page, e.g. "Configuration backup". */
  feature: string;
  /** One sentence: what turning it on gives the operator. */
  purpose: string;
}) {
  return (
    <div className="empty" role="status">
      <strong>{feature} is off.</strong> {purpose} A platform administrator can turn it on in Platform › Features.
    </div>
  );
}
