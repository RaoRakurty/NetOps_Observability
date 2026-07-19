// CorrelixLogo — brand-mark contract (owner directive 2026-07-19):
//  · the wordmark exposes exactly one accessible name ("Correlix"); the split
//    letters and the eye glyph are decorative
//  · size parameterization: letters + eye scale off one font-size; the
//    standalone eye takes an explicit box
//  · the mark is STATIC (no SMIL animation — prefers-reduced-motion safe)
//    and safe to render multiple times (unique gradient ids per instance).
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import CorrelixLogo, { CorrelixEyeO } from "./CorrelixLogo";

afterEach(cleanup);

describe("CorrelixLogo wordmark", () => {
  it("has the accessible name 'Correlix' with decorative glyphs", () => {
    render(<CorrelixLogo />);
    const logo = screen.getByRole("img", { name: "Correlix" });
    // The visible letters spell the brand around the eye-O.
    expect(logo.textContent).toBe("CRRELIX");
    // The eye SVG is hidden from AT — the name is announced exactly once.
    const svg = logo.querySelector("svg");
    expect(svg?.getAttribute("aria-hidden")).toBe("true");
  });

  it("scales letters and eye together off the size prop", () => {
    render(<CorrelixLogo size={28} />);
    const logo = screen.getByRole("img", { name: "Correlix" }) as HTMLElement;
    expect(logo.style.fontSize).toBe("28px");
    // The eye is em-sized, so it rides the same font-size.
    expect(logo.querySelector("svg")?.getAttribute("width")).toBe("1.03em");
  });
});

describe("CorrelixEyeO glyph", () => {
  it("is decorative by default and labelled when asked (compact-rail use)", () => {
    const { container } = render(<CorrelixEyeO size={26} />);
    const dec = container.querySelector("svg")!;
    expect(dec.getAttribute("aria-hidden")).toBe("true");
    expect(dec.getAttribute("width")).toBe("26");
    cleanup();
    render(<CorrelixEyeO label="Correlix" size={40} />);
    const eye = screen.getByRole("img", { name: "Correlix" });
    expect(eye.getAttribute("width")).toBe("40");
  });

  it("is static and id-collision-free across instances", () => {
    const { container } = render(
      <>
        <CorrelixEyeO />
        <CorrelixEyeO />
      </>,
    );
    // No animation of any kind (owner style rule + reduced-motion safety).
    expect(container.querySelector("animate, animateTransform, animateMotion, set")).toBeNull();
    // Gradient ids are unique per instance so multiple marks can coexist.
    const ids = Array.from(container.querySelectorAll("[id]")).map((n) => n.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
