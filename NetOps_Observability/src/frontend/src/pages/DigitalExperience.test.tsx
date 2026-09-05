import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import DigitalExperience from "./DigitalExperience";

// The point of these assertions is that the stub stays a stub. A half-built
// screen showing a few real numbers is worse than no screen: it teaches an
// operator to trust a view that is not finished.
describe("DigitalExperience", () => {
  it("renders the held state without claiming anything about health", () => {
    render(<DigitalExperience />);
    expect(screen.getByRole("region", { name: /digital experience status/i })).toBeInTheDocument();
    expect(screen.getByText(/design of record is in progress/i)).toBeInTheDocument();
  });

  it("says that collection is running, so an empty screen is not read as an outage", () => {
    render(<DigitalExperience />);
    expect(screen.getByText(/Collection is already running/i)).toBeInTheDocument();
  });
});
