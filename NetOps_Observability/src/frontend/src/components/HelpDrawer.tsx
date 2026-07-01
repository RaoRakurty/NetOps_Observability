import { useEffect } from "react";
import { useShell } from "../context/shell";
import Icon from "./Icon";

// Documentation portal, embedded in-app. Opened by the "?" affordances (the rail
// Help knob + the top-bar button). A right-docked slide-over frames the bundled
// Docusaurus site served same-origin at /docs/ (the outer nginx allows same-origin
// framing for exactly this). Product docs carry no tenant data, so there's no gate
// beyond being signed in — every operator can read them without leaving the app.
export default function HelpDrawer() {
  const { helpOpen, setHelpOpen } = useShell();

  // Esc closes the panel (matches the AI drawer).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setHelpOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [setHelpOpen]);

  return (
    <>
      <div
        className={`help-scrim${helpOpen ? " open" : ""}`}
        onClick={() => setHelpOpen(false)}
      />
      <aside
        className={`help-panel${helpOpen ? " open" : ""}`}
        aria-hidden={!helpOpen}
        role="complementary"
        aria-label="Documentation"
      >
        <header className="help-head">
          <span className="help-title">
            <Icon name="docs" size={16} />
            Documentation
          </span>
          <div className="help-actions">
            <a
              className="help-newtab"
              href="/docs/"
              target="_blank"
              rel="noopener noreferrer"
              title="Open documentation in a new tab"
            >
              Open in new tab
              <Icon name="external" size={13} />
            </a>
            <button
              className="help-close"
              type="button"
              onClick={() => setHelpOpen(false)}
              aria-label="Close documentation"
              title="Close (Esc)"
            >
              <Icon name="close" size={16} />
            </button>
          </div>
        </header>
        {/* Only mount the iframe once opened, so the docs bundle isn't fetched
            until the operator actually asks for help. */}
        {helpOpen && (
          <iframe className="help-frame" src="/docs/" title="Correlix documentation" />
        )}
      </aside>
    </>
  );
}
