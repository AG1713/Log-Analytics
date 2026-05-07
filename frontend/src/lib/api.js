const BASE = "http://localhost:8000";

const get  = (url) => fetch(`${BASE}${url}`).then(r => { if (!r.ok) throw new Error(r.statusText); return r.json(); });
const post = (url, body) => fetch(`${BASE}${url}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
const patch = (url, body) => fetch(`${BASE}${url}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then(r => r.json());
const del  = (url, body) => fetch(`${BASE}${url}`, { method: "DELETE", headers: { "Content-Type": "application/json" }, ...(body && { body: JSON.stringify(body) }) }).then(r => r.json());

export const api = {
  // ML / Dashboard
  fetchAttackSummary:   () => get("/api/metrics/network/overview"),
  fetchTrafficTimeline: (hours = 6) => get(`/api/metrics/network/timeline?hours=${hours}`),

  // Analysis page
  fetchAnalysisSummary: () => get("/api/metrics/threats/overview"),
  fetchAttackTimeline:  (hours = 6) => get(`/api/metrics/threats/timeline?hours=${hours}`),

  // Devices
  fetchDevices:         () => get("/api/devices"),

  // FIM Alerts (Moved to /api/fim)
  fetchAlerts:          (hostname) => get(`/api/fim/alerts${hostname ? `?hostname=${hostname}` : ""}`),
  deleteAlert:          (id) => del(`/api/fim/alerts/${id}`),
  clearAlerts:          (hostname) => del(`/api/fim/alerts${hostname ? `?hostname=${hostname}` : ""}`),

  // FIM Config (Moved to /api/fim)
  fetchConfig:          (hostname) => get(`/api/fim/paths${hostname ? `?hostname=${hostname}` : ""}`),
  addPath:              (path, hostname) => post("/api/fim/paths", { path, hostname }),
  removePath:           (path, hostname) => del("/api/fim/paths", { path, hostname }),
  fetchRecentFim:       (limit = 5) => get(`/api/fim/alerts/recent?limit=${limit}`),

  // Prediction logs
  fetchPredictions:     (limit = 50) => get(`/api/predictions/logs?limit=${limit}`),
  streamPredictions:    (hostname) => {
    const params = hostname ? `?hostname=${hostname}` : "";
    return new EventSource(`${BASE}/api/predictions/stream${params}`);
  },

  // Network logs
  fetchNetworkLogs:     (limit = 50) => get(`/api/network/logs?limit=${limit}`),
  streamNetworkLogs:    (hostname) => {
    const params = hostname ? `?hostname=${hostname}` : "";
    return new EventSource(`${BASE}/api/network/stream${params}`);
  },

  // Attack Alerts
  fetchAttackAlerts:          (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v != null));
    const query = new URLSearchParams(cleanParams).toString();
    return get(`/api/attack-alerts${query ? `?${query}` : ""}`);
  },
  fetchRecentAttacks:  (limit = 5) => get(`/api/attack-alerts/recent?limit=${limit}`),
  toggleAttackAlertStatus:    (id) => patch(`/api/attack-alerts/${id}`, {}), 
  deleteAttackAlert:          (id) => del(`/api/attack-alerts/${id}`), 
  clearAttackAlerts:          (hostname) => del(`/api/attack-alerts${hostname ? `?hostname=${hostname}` : ""}`),

  // Agent Download 
  getAgentDownloadUrl: (osType) => `${BASE}/api/metrics/agent?os_type=${osType}&t=${Date.now()}`,
};