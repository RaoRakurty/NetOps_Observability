import { useEffect, useState } from "react";
import { api, Device } from "../services/api";

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState({ id: "", name: "", address: "" });

  const load = async () => {
    try {
      const list = await api.devices();
      setDevices(list ?? []);
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!draft.id || !draft.address) return;
    setBusy(true);
    try {
      await api.upsertDevice(draft);
      setDraft({ id: "", name: "", address: "" });
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    if (!confirm(`Delete ${id}?`)) return;
    await api.deleteDevice(id);
    await load();
  };

  return (
    <>
      <div className="card">
        <h2>Add device</h2>
        <form onSubmit={submit} style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <input
            placeholder="id"
            value={draft.id}
            onChange={(e) => setDraft({ ...draft, id: e.target.value })}
          />
          <input
            placeholder="name"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            placeholder="address"
            value={draft.address}
            onChange={(e) => setDraft({ ...draft, address: e.target.value })}
          />
          <button disabled={busy} type="submit">
            {busy ? "Saving…" : "Save"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Inventory ({devices.length})</h2>
        {error && <p style={{ color: "var(--bad)" }}>{error}</p>}
        {devices.length === 0 ? (
          <div className="empty">No devices yet — discovery hasn't returned anything.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Name</th>
                <th>Address</th>
                <th>Source</th>
                <th>Last seen</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id}>
                  <td>{d.id}</td>
                  <td>{d.name || "—"}</td>
                  <td>{d.address}</td>
                  <td>
                    <span className="badge good">{d.source}</span>
                  </td>
                  <td>{new Date(d.last_seen).toLocaleString()}</td>
                  <td>
                    <button onClick={() => remove(d.id)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
