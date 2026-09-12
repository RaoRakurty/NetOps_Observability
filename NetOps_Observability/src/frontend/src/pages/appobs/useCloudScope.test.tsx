// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// useCloudScope.test — the URL IS the scope state (Wave 2 #5): mutations write
// the hash, hashchange folds it back, refresh/back/pasted links reproduce the
// exact view, and the drawer's ?inv= param survives every scope mutation.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor, cleanup } from "@testing-library/react";
import { useCloudScope } from "./useCloudScope";
import { scopeFromHash } from "./scopeUrl";

function Harness() {
  const ctl = useCloudScope();
  return (
    <>
      <div data-testid="providers">{ctl.scope.providers.join(",")}</div>
      <div data-testid="range">{ctl.scope.rangeMinutes}</div>
      <div data-testid="active">{String(ctl.active)}</div>
      <button onClick={() => ctl.add("providers", "aws")}>add-aws</button>
      <button onClick={() => ctl.add("providers", "azure")}>add-azure</button>
      <button onClick={() => ctl.remove("providers", "aws")}>rm-aws</button>
      <button onClick={() => ctl.setRangeMinutes(7 * 24 * 60)}>range-7d</button>
      <button onClick={ctl.clearFilters}>clear</button>
    </>
  );
}

beforeEach(() => { location.hash = "#/monitoring/appobs"; });
afterEach(cleanup);

describe("useCloudScope", () => {
  it("adds/removes values, mirrored to the URL and back", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByText("add-aws"));
    await waitFor(() => expect(screen.getByTestId("providers").textContent).toBe("aws"));
    expect(location.hash).toContain("provider=aws");
    fireEvent.click(screen.getByText("add-azure"));
    await waitFor(() => expect(screen.getByTestId("providers").textContent).toBe("aws,azure"));
    fireEvent.click(screen.getByText("rm-aws"));
    await waitFor(() => expect(screen.getByTestId("providers").textContent).toBe("azure"));
    expect(scopeFromHash(location.hash).providers).toEqual(["azure"]);
  });

  it("initializes from a pasted/refreshed URL", () => {
    location.hash = "#/monitoring/appobs?provider=gcp&range=7d";
    render(<Harness />);
    expect(screen.getByTestId("providers").textContent).toBe("gcp");
    expect(screen.getByTestId("range").textContent).toBe(String(7 * 24 * 60));
    expect(screen.getByTestId("active").textContent).toBe("true");
  });

  it("range changes keep filters; clearing filters keeps the range", async () => {
    render(<Harness />);
    fireEvent.click(screen.getByText("add-aws"));
    fireEvent.click(screen.getByText("range-7d"));
    await waitFor(() => expect(screen.getByTestId("range").textContent).toBe(String(7 * 24 * 60)));
    expect(screen.getByTestId("providers").textContent).toBe("aws");
    fireEvent.click(screen.getByText("clear"));
    await waitFor(() => expect(screen.getByTestId("providers").textContent).toBe(""));
    expect(screen.getByTestId("range").textContent).toBe(String(7 * 24 * 60));
  });

  it("never clobbers the investigation drawer's inv param", async () => {
    location.hash = "#/monitoring/appobs?inv=P-027379";
    render(<Harness />);
    fireEvent.click(screen.getByText("add-aws"));
    await waitFor(() => expect(location.hash).toContain("provider=aws"));
    expect(location.hash).toContain("inv=P-027379");
    fireEvent.click(screen.getByText("clear"));
    await waitFor(() => expect(location.hash).not.toContain("provider=aws"));
    expect(location.hash).toContain("inv=P-027379");
  });
});
