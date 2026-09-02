// ExposureStories.test.tsx — the hero list and its reuse of the RCA workspace.
// A story id that is not this tenant's must read as "not available", never as
// an empty workspace that implies the story exists.

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";

const securityExposureStories = vi.fn();
const securityExposureStory = vi.fn();

vi.mock("../../services/api", () => ({
  api: {
    securityExposureStories: (...a: unknown[]) => securityExposureStories(...a),
    securityExposureStory: (...a: unknown[]) => securityExposureStory(...a),
  },
}));
vi.mock("../../tabs/Correlations", () => ({
  CorrelationDetail: ({ id }: { id: string }) => <div>RCA workspace for {id}</div>,
}));

import ExposureStories, { storyIdFromHash } from "./ExposureStories";
import { STORY } from "./fixtures";

afterEach(() => { cleanup(); window.location.hash = ""; });
beforeEach(() => {
  securityExposureStories.mockReset(); securityExposureStory.mockReset();
  securityExposureStories.mockResolvedValue([STORY]);
  securityExposureStory.mockResolvedValue({ object: STORY, edges: [] });
  window.location.hash = "";
});

describe("storyIdFromHash", () => {
  it("reads the id from a story deep link and decodes it", () => {
    expect(storyIdFromHash("#/security/stories/corr-9")).toBe("corr-9");
    expect(storyIdFromHash("#/security/stories/corr%2F9")).toBe("corr/9");
  });
  it("returns empty for the list route and for any other route", () => {
    expect(storyIdFromHash("#/security/stories")).toBe("");
    expect(storyIdFromHash("#/security/exposures")).toBe("");
    expect(storyIdFromHash("")).toBe("");
  });
});

describe("Exposure Stories", () => {
  it("lists the tenant's stories with verdict, owner and confidence", async () => {
    render(<ExposureStories />);
    expect(await screen.findByText(/management plane is reachable from the ISP seam/)).toBeTruthy();
    expect(screen.getByText(/isp · suspected · confidence 72%/)).toBeTruthy();
    expect(screen.getByText("14 observations")).toBeTruthy();
  });

  it("an empty list says nothing correlated, not that nothing is wrong", async () => {
    securityExposureStories.mockResolvedValue([]);
    render(<ExposureStories />);
    expect(await screen.findByText(/means nothing correlated, not that nothing is wrong/i)).toBeTruthy();
  });

  it("opening a story reuses the existing RCA workspace", async () => {
    render(<ExposureStories />);
    fireEvent.click(await screen.findByText(/management plane is reachable/));
    await waitFor(() => expect(screen.getByText("RCA workspace for corr-9")).toBeTruthy());
    expect(securityExposureStory).toHaveBeenCalledWith("corr-9");
  });

  it("a foreign or unknown id reads as not available, never as an empty workspace", async () => {
    securityExposureStory.mockRejectedValue(new Error("404 Not Found"));
    window.location.hash = "#/security/stories/somebody-elses";
    render(<ExposureStories />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/not available to you: 404 Not Found/);
    expect(screen.queryByText(/RCA workspace/)).toBeNull();
  });
});
