// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// PageHeader — the top of a page: an icon in a small bordered tile, the title,
// a quiet count badge and the page's actions on the right (outlined buttons).
// docs/design/visual-language.md › Components.

import type { ReactNode } from "react";
import Icon from "../Icon";
import "./kit.css";

export interface PageHeaderProps {
  /** A glyph from Icon.tsx — usually the page's own menu icon. */
  icon: string;
  title: string;
  /** Item count shown beside the title (omit when the page has no list). */
  count?: number;
  /** One plain line under the title, when the page needs it. */
  subtitle?: ReactNode;
  /** Right-aligned actions: OutlinedButton(s), an AskIris, a live chip. */
  actions?: ReactNode;
}

export default function PageHeader({ icon, title, count, subtitle, actions }: PageHeaderProps) {
  return (
    <header className="kit-ph">
      <span className="kit-ph-tile" aria-hidden><Icon name={icon} size={17} /></span>
      <h1 className="kit-ph-title">{title}</h1>
      {count !== undefined && <span className="kit-ph-count" aria-label={`${count} items`}>{count}</span>}
      {actions && <div className="kit-ph-actions">{actions}</div>}
      {subtitle && <p className="kit-ph-sub">{subtitle}</p>}
    </header>
  );
}

export interface OutlinedButtonProps {
  children?: ReactNode;
  icon?: string;
  /** Accessible name; required when the button shows only an icon. */
  label?: string;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  disabled?: boolean;
  title?: string;
  /** Trailing chevron ("Open ›"). */
  chevron?: boolean;
  testId?: string;
}

/** The outlined button used for page and row actions ("Add device", "Open ›"). */
export function OutlinedButton({ children, icon, label, onClick, disabled, title, chevron, testId }: OutlinedButtonProps) {
  const iconOnly = !children;
  return (
    <button
      type="button"
      className={`kit-obtn${iconOnly ? " kit-icon-only" : ""}`}
      onClick={onClick}
      disabled={disabled}
      title={title ?? label}
      aria-label={iconOnly ? label : undefined}
      data-testid={testId}
    >
      {icon && <Icon name={icon} size={15} />}
      {children}
      {chevron && <Icon name="chevron-right" size={14} />}
    </button>
  );
}
