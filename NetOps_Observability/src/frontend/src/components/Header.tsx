import { AuthUser, Health } from "../services/api";

type Props = {
  health: Health | null;
  user: AuthUser;
  onLogout: () => void;
};

export default function Header({ health, user, onLogout }: Props) {
  const ok = health?.status === "healthy";
  return (
    <header className="app-header">
      <h1>NetOps Observability</h1>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <span className={`health${ok ? "" : " bad"}`}>
          <span className="dot" />
          {ok ? `Healthy — v${health?.version}` : "Disconnected"}
        </span>
        <span style={{ color: "var(--muted)", fontSize: 12 }}>
          {user.username} <span style={{ opacity: 0.6 }}>({user.role})</span>
        </span>
        <button onClick={onLogout} style={{ fontSize: 12, padding: "4px 10px" }}>
          Sign out
        </button>
      </div>
    </header>
  );
}
