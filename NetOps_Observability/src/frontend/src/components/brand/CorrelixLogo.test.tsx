// CorrelixLogo — brand-mark contract (owner selection 2026-07-21, candidate 5):
//  · the wordmark exposes exactly one accessible name ("Correlix"); the eye
//    glyph and the split letters are decorative
//  · the eye REPLACES the O (C‹eye›RRELIX — candidate 5 lockup)
//  · size parameterization: letters + eye scale off one font-size; the
//    standalone eye takes an explicit box
//  · the mark is STATIC (no SMIL animation — prefers-reduced-motion safe)
//    and safe to render multiple times (unique gradient/clip ids per instance).
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import CorrelixLogo, { CorrelixEye } from "./CorrelixLogo";

afterEach(cleanup);

describe("CorrelixLogo wordmark", () => {
  it("has the accessible name 'Correlix' with decorative glyphs", () => {
    render(<CorrelixLogo />);
    const logo = screen.getByRole("img", { name: "Correlix" });
    // The eye IS the O (candidate 5 lockup) — the letters spell CRRELIX around it.
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
    expect(logo.querySelector("svg")?.getAttribute("width")).toBe("1.5em");
  });
});

describe("CorrelixEye glyph", () => {
  it("is decorative by default and labelled when asked (compact-rail use)", () => {
    const { container } = render(<CorrelixEye size={26} />);
    const dec = container.querySelector("svg")!;
    expect(dec.getAttribute("aria-hidden")).toBe("true");
    expect(dec.getAttribute("width")).toBe("26");
    cleanup();
    render(<CorrelixEye label="Correlix" size={40} />);
    const eye = screen.getByRole("img", { name: "Correlix" });
    expect(eye.getAttribute("width")).toBe("40");
  });

  it("is static and id-collision-free across instances", () => {
    const { container } = render(
      <>
        <CorrelixEye />
        <CorrelixEye />
      </>,
    );
    // No animation of any kind (owner style rule + reduced-motion safety).
    expect(container.querySelector("animate, animateTransform, animateMotion, set")).toBeNull();
    // Gradient/clip ids are unique per instance so multiple marks can coexist.
    const ids = Array.from(container.querySelectorAll("[id]")).map((n) => n.id);
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
