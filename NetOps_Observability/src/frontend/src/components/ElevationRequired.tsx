// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// ElevationRequired — the shell-level answer to a step-up refusal.
//
// Some actions (opening a vendor case, a device shell, granting a standing
// role) are ELEVATED-ONLY when the deployment runs a second, separately
// governed identity provider for just-in-time access. A standing session that
// attempts one gets a 403 that NAMES the provider to use, and this is what
// turns that into something the operator can act on: a dialog with the button.
//
// WHY A SHELL COMPONENT AND NOT A PER-PAGE ERROR. The refusal can arrive from
// any elevated-only call anywhere in the product, including panels this file
// knows nothing about. api.ts raises one named window event on the refusal (the
// AskIris seam, same reasoning), the shell listens once, and no page has to
// learn what elevation is to behave correctly when it hits one.
//
// The event carries no data of its own beyond what the SERVER put in the
// refusal — the provider ids come from the server's own configured list, and
// the sign-in URL is minted by api.ssoLoginUrl (which arms the login-CSRF
// nonce), so nothing on the wire steers where the browser is sent.

import { useEffect, useState } from "react";
import { api, ELEVATION_REQUIRED_EVENT, type ElevationRefusal } from "../services/api";
import { Modal } from "./ui";

export default function ElevationRequired() {
  const [refusal, setRefusal] = useState<ElevationRefusal | null>(null);

  useEffect(() => {
    const onRefusal = (e: Event) => setRefusal((e as CustomEvent<ElevationRefusal>).detail);
    window.addEventListener(ELEVATION_REQUIRED_EVENT, onRefusal);
    return () => window.removeEventListener(ELEVATION_REQUIRED_EVENT, onRefusal);
  }, []);

  if (!refusal) return null;
  return (
    <Modal title="Elevated access" onClose={() => setRefusal(null)}>
      <div className="auth-form adm">
        <p role="alert">{refusal.error}</p>
        {refusal.providers.length === 0 ? (
          <p className="adm-line">Ask an administrator to configure an elevation provider.</p>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {refusal.providers.map((p) => (
              <button
                key={p.id || "default"}
                type="button"
                className="btn-accent"
                onClick={() => { window.location.href = api.ssoLoginUrl(p.id); }}
              >
                Sign in through {p.name}
              </button>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}
