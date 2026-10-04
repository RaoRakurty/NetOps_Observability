// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// JsonDiff — "show exactly what changed" (tracker 337 N-E3, design Part 2 §29).
//
// Two layouts over one comparison (jsonDiff.ts):
//   · Side by side — before | after per setting (or per line for plain text),
//     each row labelled Changed / Added / Removed in words, not colour alone;
//   · Line by line — the SAME unified view the device Configuration tab uses
//     (components/ConfigDiffView), fed a unified text built from the comparison.
//
// Before/after text comes from a change record: hostile input. Everything is an
// escaped React text node; there is no HTML sink.

import { useMemo, useState } from "react";
import { Segmented } from "../components/ui";
import { ConfigDiffView } from "../components/ConfigDiffView";
import { buildDiff, toUnified, type DiffKind } from "./jsonDiff";

type Layout = "side" | "unified";

const KIND_WORD: Record<DiffKind, string> = {
  same: "Unchanged",
  changed: "Changed",
  added: "Added",
  removed: "Removed",
};

export default function JsonDiff({
  before,
  after,
  title = "What changed",
}: {
  before: unknown;
  after: unknown;
  title?: string;
}) {
  const [layout, setLayout] = useState<Layout>("side");
  const model = useMemo(() => buildDiff(before, after), [before, after]);
  const identical = model.added + model.removed + model.changed === 0;

  if (model.rows.length === 0) {
    return <p className="iris-empty">No before or after was recorded.</p>;
  }

  return (
    <section className="iris-diff" aria-label={title}>
      <div className="iris-diff-head">
        <h3 className="iris-h">{title}</h3>
        <Segmented<Layout>
          value={layout}
          onChange={setLayout}
          ariaLabel="Diff layout"
          options={[
            { value: "side", label: "Side by side" },
            { value: "unified", label: "Line by line" },
          ]}
        />
      </div>
      <p className="iris-note">
        {identical
          ? "Before and after are identical."
          : `${model.changed} changed · ${model.added} added · ${model.removed} removed`}
      </p>
      {model.truncated && (
        <p className="iris-notice" role="status">
          This change is too large to show in full — only the first part is compared.
        </p>
      )}
      {layout === "side" ? (
        <div className="iris-diff-table" role="table" aria-label={`${title}, side by side`}>
          <div className="iris-diff-row iris-diff-hdr" role="row">
            <span role="columnheader">{model.mode === "structured" ? "Setting" : "Line"}</span>
            <span role="columnheader">Before</span>
            <span role="columnheader">After</span>
          </div>
          {model.rows.map((r, i) => (
            <div key={i} className={`iris-diff-row kind-${r.kind}`} role="row">
              <span role="cell" className="mono">
                {r.path}
                {r.kind !== "same" && <span className="iris-diff-kind"> · {KIND_WORD[r.kind]}</span>}
              </span>
              <span role="cell" className="mono iris-diff-before">
                {r.before ?? <span className="iris-muted">(not present)</span>}
              </span>
              <span role="cell" className="mono iris-diff-after">
                {r.after ?? <span className="iris-muted">(not present)</span>}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <ConfigDiffView
          title={title}
          diff={{
            unified: toUnified(model),
            added: model.added + model.changed,
            removed: model.removed + model.changed,
            // The bound is ours, not the server's, and is already stated above.
            truncated: false,
          }}
        />
      )}
    </section>
  );
}
