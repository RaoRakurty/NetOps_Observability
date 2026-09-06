import React from "react";
import ReactDOM from "react-dom/client";
// Fonts are NOT imported here any more. Importing @fontsource CSS from TS made
// Vite emit 99 hashed .woff/.woff2 files (1.36 MB) under content-hashed URLs
// that index.html cannot preload, and it pinned the UI to four discrete static
// weights — so body text rendered at 400 and looked thin. The three variable
// faces (Inter, JetBrains Mono, Space Grotesk — all SIL OFL-1.1) are now
// checked into public/fonts/ and declared once, at the top of ./styles.css.
// See public/fonts/README.md and docs/design/TYPOGRAPHY_2026-09-06.md.
import App from "./App";
import { captureSSORedirect } from "./services/api";
import { applyPrefs } from "./theme/prefs";
import "./styles.css";

// Reflect the saved theme/density onto <html> before first paint (no flash).
applyPrefs();

// If we arrived here from the SSO callback redirect, capture the session from
// the URL fragment (and stash any error for Login to show) before first render.
const ssoError = captureSSORedirect();
if (ssoError) sessionStorage.setItem("netops_sso_error", ssoError);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
