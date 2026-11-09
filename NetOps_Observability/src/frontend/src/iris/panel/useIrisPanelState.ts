// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useIrisPanelState — the Iris panel's window state as App holds it (tracker
// 339, design §15). The pure reducer and storage codec live in
// irisPanelState.ts; this hook is only their wiring:
//
//   · starts closed, with the remembered mode, docked width and pre-expand
//     mode of the signed-in PRINCIPAL (owner = irisOwnerKey(user));
//   · a change of principal — sign-in, sign-out, an account switch in the same
//     tab — reloads that principal's preferences (closed), so a shared browser
//     never hands one operator's layout to the next;
//   · every change of a remembered value is written back under its owner.
//     Owner and values change together in one reducer state, so a value is
//     never written under the wrong owner.

import { useEffect, useReducer, type Dispatch } from "react";
import { irisReducer, loadIrisState, saveIrisState, type IrisAction, type IrisPanelState } from "./irisPanelState";

export function useIrisPanelState(owner: string | null): [IrisPanelState, Dispatch<IrisAction>] {
  const [iris, dispatch] = useReducer(irisReducer, owner, (o: string | null) => loadIrisState(o));
  useEffect(() => {
    if (iris.owner !== owner) dispatch({ type: "hydrate", state: loadIrisState(owner) });
  }, [owner]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    // false = no owner (signed out), or storage refused the write (private
    // window, blocked site data): the choice still holds for this page load.
    saveIrisState(iris);
  }, [iris.owner, iris.lastOpen, iris.beforeExpand, iris.width]); // eslint-disable-line react-hooks/exhaustive-deps
  return [iris, dispatch];
}
