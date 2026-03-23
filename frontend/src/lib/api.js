const BASE = "http://localhost:8000";

const get  = (url) => fetch(`${BASE}${url}`).then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); });
const post = (url, body) => fetch(`${BASE}${url}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
const del  = (url, body) => fetch(`${BASE}${url}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, ...(body && { body: JSON.stringify(body) }) }).then(r => r.json());

export const api = {
  // ML
  fetchAttackSummary:  () => get("/attack_summary"),

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

  // Network
  fetchNetworkLogs:    (hostname, limit = 50) => get(`/api/network/logs?limit=${limit}${hostname ? `&hostname=${hostname}` : ""}`),
  fetchNetworkSummary: (hostname) => get(`/api/network/summary${hostname ? `?hostname=${hostname}` : ""}`),
};