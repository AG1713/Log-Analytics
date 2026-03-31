const BASE = "http://localhost:8000";

const get  = (url) => fetch(`${BASE}${url}`).then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); });
const post = (url, body) => fetch(`${BASE}${url}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
const del  = (url, body) => fetch(`${BASE}${url}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, ...(body && { body: JSON.stringify(body) }) }).then(r => r.json());

export const api = {
  // ML / Dashboard
  fetchAttackSummary:  () => get("/api/attack-summary"),   // ← fixed: was /attack_summary (old CSV endpoint)
  fetchAttackTimeline: (hours = 6) => get(`/api/attack-timeline?hours=${hours}`),  // ← new
  fetchNetworkLogs:    (limit = 50) => get(`/api/network/logs?limit=${limit}`),     // ← new (initial table load)

  // Devices
  fetchDevices:        () => get("/api/devices"),

  // Alerts
  fetchAlerts:         (hostname) => get(`/api/alerts${hostname ? `?hostname=${hostname}` : ""}`),
  deleteAlert:         (id) => del(`/api/alerts/${id}`),
  clearAlerts:         (hostname) => del(`/api/alerts${hostname ? `?hostname=${hostname}` : ""}`),

  // FIM Config
  fetchConfig:         (hostname) => get(`/api/config${hostname ? `?hostname=${hostname}` : ""}`),
  addPath:             (path, hostname) => post("/api/add_path", { path, hostname }),
  removePath:          (path, hostname) => del("/api/config/path", { path, hostname }),

  // Network stream (SSE)
  streamNetwork: (hostname) => {
    const params = hostname ? `?hostname=${hostname}` : "";
    return new EventSource(`${BASE}/api/network/stream${params}`);
  },
};