import React from "react";
import ReactDOM from "react-dom/client";
// Inter — bundled (no external CDN) so the modern type renders offline.
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";
// Geist (variable) — the shell-v2 UI face: elegant, legible at small sizes,
// in the premium/operations zone. Bundled offline like Inter.
import "@fontsource-variable/geist";
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
