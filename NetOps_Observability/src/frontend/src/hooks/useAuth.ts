import { useEffect, useState } from "react";
import { api, AuthUser, getToken, onAuthChange } from "../services/api";

// useAuth — single source of truth for "is the user signed in?".
// We model state as { loading, user }. user === null means signed out.

export function useAuth() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // On mount: if we have a token, validate it by calling /api/auth/me.
  // If that fails (401), api.ts will already have cleared the token and
  // fired an auth-change event, so we just react to that.
  useEffect(() => {
    let alive = true;
    const init = async () => {
      const tok = getToken();
      if (!tok) {
        if (alive) setLoading(false);
        return;
      }
      try {
        const u = await api.me();
        if (alive) {
          setUser(u);
          setLoading(false);
        }
      } catch {
        if (alive) {
          setUser(null);
          setLoading(false);
        }
      }
    };
    init();
    const off = onAuthChange((signedIn) => {
      if (!signedIn) setUser(null);
    });
    return () => {
      alive = false;
      off();
    };
  }, []);

  const refresh = async () => {
    try {
      const u = await api.me();
      setUser(u);
    } catch {
      setUser(null);
    }
  };

  return { user, loading, refresh, logout: () => { api.logout(); setUser(null); } };
}
