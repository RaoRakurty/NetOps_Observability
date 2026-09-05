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

  // Layout contract (owner report 2026-09-05). A story row is a three-cell
  // grid: stripe · main · observation count. The count must stay a SIBLING of
  // the text cell — when the middle cell carried the app shell's global `main`
  // class it inherited grid-area:main and painted across the count. happy-dom
  // applies no CSS, so this asserts the structure the CSS depends on.
  it("keeps the observation count a sibling cell, and reuses no app-shell class", async () => {
    const long = {
      ...STORY,
      correlation_id: "corr-long",
      top_hypothesis:
        "dc1-border-leaf-01.pod3.example.net:HundredGigE0/0/0/17.3001 management plane is reachable from the ISP seam",
      owner: "dc1-border-leaf-01.pod3.example.net/HundredGigE0/0/0/17.3001",
      signal_count: 1284,
    };
    securityExposureStories.mockResolvedValue([long]);
    const { container } = render(<ExposureStories />);
    await screen.findByText("1284 observations");
    const row = container.querySelector(".sec-row")!;
    const cells = [...row.children].map((c) => c.className.split(" ")[0]);
    expect(cells).toEqual(["sec-stripe", "sec-main", "fix"]);
    // the count is its own cell, never nested in the text cell
    expect(row.querySelector(".sec-main .fix")).toBeNull();
    expect(row.querySelector(".fix")!.textContent).toBe("1284 observations");
    // headline and sub-line are separate elements inside the shrinking cell
    expect(row.querySelector(".sec-main > b")).toBeTruthy();
    expect(row.querySelector(".sec-main > .sub")).toBeTruthy();
    // `.rail`/`.main` are app-shell element rules in styles.css — never here.
    expect(container.querySelectorAll(".rail, .main").length).toBe(0);
  });

  it("a foreign or unknown id reads as not available, never as an empty workspace", async () => {
    securityExposureStory.mockRejectedValue(new Error("404 Not Found"));
    window.location.hash = "#/security/stories/somebody-elses";
    render(<ExposureStories />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/not available to you: 404 Not Found/);
    expect(screen.queryByText(/RCA workspace/)).toBeNull();
  });
});
