import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";

const COLORS = {
  bg:     "#060d1a",
  card:   "#0d1626",
  border: "#0f1e36",
  text:   "#e2f0ff",
  muted:  "#2a4a6a",
  cyan:   "#00d4ff",
  green:  "#10b981",
  red:    "#ef4444",
  amber:  "#f59e0b",
  blue:   "#06b6d4",
};

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high:     "#f59e0b",
  medium:   "#06b6d4",
  low:      "#10b981",
};

const TYPE_META = {
  FIM_MODIFICATION: { label: "Modified", color: "#f59e0b", accent: "#f59e0b22" },
  FIM_DELETION:     { label: "Deleted",  color: "#ef4444", accent: "#ef444422" },
  FIM_NEW_FILE:     { label: "New File", color: "#06b6d4", accent: "#06b6d422" },
};

const PATH_TREE = [
  {
    label: "etc", path: "/etc", children: [
      { label: "nginx",   path: "/etc/nginx" },
      { label: "apache2", path: "/etc/apache2" },
      { label: "ssh",     path: "/etc/ssh" },
      { label: "cron.d",  path: "/etc/cron.d" },
      { label: "passwd",  path: "/etc/passwd" },
    ]
  },
  {
    label: "var", path: "/var", children: [
      {
        label: "www", path: "/var/www", children: [
          { label: "html", path: "/var/www/html" },
        ]
      },
      {
        label: "log", path: "/var/log", children: [
          { label: "nginx",    path: "/var/log/nginx" },
          { label: "apache2",  path: "/var/log/apache2" },
          { label: "auth.log", path: "/var/log/auth.log" },
          { label: "syslog",   path: "/var/log/syslog" },
        ]
      },
    ]
  },
  {
    label: "root", path: "/root", children: [
      { label: ".ssh",    path: "/root/.ssh" },
      { label: ".bashrc", path: "/root/.bashrc" },
    ]
  },
  {
    label: "home", path: "/home", children: [
      { label: "ubuntu",   path: "/home/ubuntu" },
      { label: "www-data", path: "/home/www-data" },
    ]
  },
  {
    label: "usr", path: "/usr", children: [
      { label: "local/bin", path: "/usr/local/bin" },
      { label: "share",     path: "/usr/share" },
    ]
  },
];

const Card = ({ children, style = {} }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: "16px", ...style }}>
    {children}
  </div>
);

const CardLabel = ({ children }) => (
  <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "10px" }}>
    {children}
  </div>
);

const SeverityDot = ({ severity }) => (
  <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
    <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: SEVERITY_COLORS[severity] || COLORS.muted, display: "inline-block" }} />
    <span style={{ color: SEVERITY_COLORS[severity] || COLORS.muted, textTransform: "capitalize", fontSize: "11px" }}>{severity}</span>
  </span>
);

const TreeNode = ({ node, depth = 0, monitoredPaths, onAdd }) => {
  const [open, setOpen] = useState(false);
  const isMonitored = monitoredPaths.includes(node.path);
  const hasChildren = node.children?.length > 0;

  return (
    <div>
      <div
        style={{
          display: "flex", alignItems: "center", gap: "6px",
          padding: "4px 6px", paddingLeft: `${depth * 14 + 6}px`,
          borderRadius: "5px", cursor: "pointer",
          background: isMonitored ? `${COLORS.cyan}0d` : "transparent",
          border: isMonitored ? `1px solid ${COLORS.cyan}22` : "1px solid transparent",
          marginBottom: "2px",
        }}
        onClick={() => hasChildren && setOpen(o => !o)}
      >
        <span style={{ fontSize: "9px", color: COLORS.muted, width: "10px", flexShrink: 0 }}>
          {hasChildren ? (open ? "▼" : "▶") : ""}
        </span>
        <span style={{ fontSize: "11px" }}>{hasChildren ? "📁" : "📄"}</span>
        <span style={{ fontSize: "11px", color: isMonitored ? COLORS.cyan : COLORS.text, fontFamily: "monospace", flex: 1 }}>
          {node.label}
        </span>
        {!isMonitored && (
          <button
            onClick={e => { e.stopPropagation(); onAdd(node.path); }}
            style={{ fontSize: "10px", padding: "1px 7px", borderRadius: "4px", border: `1px solid ${COLORS.cyan}44`, background: `${COLORS.cyan}11`, color: COLORS.cyan, cursor: "pointer", opacity: 0.7 }}
          >
            + Add
          </button>
        )}
        {isMonitored && (
          <span style={{ fontSize: "9px", color: COLORS.cyan, opacity: 0.7 }}>● watching</span>
        )}
      </div>
      {open && hasChildren && node.children.map((child, i) => (
        <TreeNode key={i} node={child} depth={depth + 1} monitoredPaths={monitoredPaths} onAdd={onAdd} />
      ))}
    </div>
  );
};

export default function Fim() {
  const queryClient = useQueryClient();

  const [selectedDevice, setSelectedDevice] = useState(null);
  const [newPath, setNewPath]               = useState("");
  const [filter, setFilter]                 = useState("ALL");
  const [pathMsg, setPathMsg]               = useState(null);

  // --- Queries ---
  const { data: alertsData = [], isLoading: alertsLoading } = useQuery({
    queryKey: ["alerts", selectedDevice],
    queryFn:  () => api.fetchAlerts(selectedDevice),
    refetchInterval: 10000,
  });

  const { data: configData, isLoading: configLoading } = useQuery({
    queryKey: ["config", selectedDevice],
    queryFn:  () => api.fetchConfig(selectedDevice),
    refetchInterval: 10000,
  });

  const { data: devicesData } = useQuery({
    queryKey: ["devices"],
    queryFn:  api.fetchDevices,
    refetchInterval: 30000,
  });

  const alerts  = alertsData || [];
  const paths   = configData?.paths   || [];
  const devices = devicesData?.devices || [];
  const loading = alertsLoading || configLoading;

  // --- Mutations ---
  const addPathMutation = useMutation({
    mutationFn: ({ path, hostname }) => api.addPath(path, hostname),
    onSuccess: (data) => {
      if (data.status === "success") {
        setPathMsg({ type: "success", text: `Added: ${data.added}` });
        setNewPath("");
        setTimeout(() => setPathMsg(null), 3000);
      } else {
        setPathMsg({ type: "error", text: data.message || "Failed" });
      }
      queryClient.invalidateQueries({ queryKey: ["config"] });
    },
    onError: () => setPathMsg({ type: "error", text: "Request failed" }),
  });

  const removePathMutation = useMutation({
    mutationFn: ({ path, hostname }) => api.removePath(path, hostname),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["config"] }),
  });

  const deleteAlertMutation = useMutation({
    mutationFn: (id) => api.deleteAlert(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  const clearAlertsMutation = useMutation({
    mutationFn: () => api.clearAlerts(selectedDevice),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["alerts"] }),
  });

  // --- Handlers ---
  const handleAddPath    = (pathToAdd = null) => {
    const p = pathToAdd || newPath.trim();
    if (!p) return;
    addPathMutation.mutate({ path: p, hostname: selectedDevice });
  };
  const handleRemovePath  = (path) => removePathMutation.mutate({ path, hostname: selectedDevice });
  const handleDeleteAlert = (id)   => deleteAlertMutation.mutate(id);
  const handleClearAlerts = ()     => clearAlertsMutation.mutate();

  const totalModified  = alerts.filter(a => a.type === "FIM_MODIFICATION").length;
  const totalDeleted   = alerts.filter(a => a.type === "FIM_DELETION").length;
  const totalNew       = alerts.filter(a => a.type === "FIM_NEW_FILE").length;
  const filteredAlerts = filter === "ALL" ? alerts : alerts.filter(a => a.type === filter);

  if (loading) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontFamily: "monospace" }}>
      LOADING...
    </div>
  );

  return (
    <div style={{ background: COLORS.bg, color: COLORS.text, minHeight: "100vh", padding: "24px 28px" }}>

      {/* Header */}
      <div className="flex justify-between items-start mb-4">
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: COLORS.text, margin: "0 0 3px", letterSpacing: "-0.02em" }}>
            File Integrity Monitor
          </h1>
          <p style={{ fontSize: "10px", color: COLORS.muted, margin: 0, fontFamily: "monospace", letterSpacing: "0.06em" }}>
            LIVE · Auto-refreshes every 10s
          </p>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button
            onClick={handleClearAlerts}
            style={{ padding: "5px 14px", borderRadius: "6px", border: `1px solid ${COLORS.red}33`, background: `${COLORS.red}11`, fontSize: "12px", color: COLORS.red, cursor: "pointer" }}
          >
            Clear Alerts
          </button>
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ["alerts"] })}
            style={{ padding: "5px 14px", borderRadius: "6px", border: `1px solid ${COLORS.cyan}33`, background: `${COLORS.cyan}11`, fontSize: "12px", color: COLORS.cyan, cursor: "pointer" }}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Device Tabs */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "16px", flexWrap: "wrap" }}>
        <button
          onClick={() => setSelectedDevice(null)}
          style={{
            padding: "5px 14px", borderRadius: "6px", fontSize: "11px", cursor: "pointer",
            border: `1px solid ${!selectedDevice ? COLORS.cyan + "55" : COLORS.border}`,
            background: !selectedDevice ? `${COLORS.cyan}11` : "transparent",
            color: !selectedDevice ? COLORS.cyan : COLORS.muted,
          }}
        >
          All Devices
          <span style={{ marginLeft: "6px", fontFamily: "monospace", fontSize: "10px" }}>{alerts.length}</span>
        </button>
        {devices.map(device => (
          <button
            key={device}
            onClick={() => setSelectedDevice(device)}
            style={{
              padding: "5px 14px", borderRadius: "6px", fontSize: "11px", cursor: "pointer",
              border: `1px solid ${selectedDevice === device ? COLORS.cyan + "55" : COLORS.border}`,
              background: selectedDevice === device ? `${COLORS.cyan}11` : "transparent",
              color: selectedDevice === device ? COLORS.cyan : COLORS.muted,
              fontFamily: "monospace",
            }}
          >
            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: COLORS.green, display: "inline-block", marginRight: "6px" }} />
            {device}
          </button>
        ))}
        {devices.length === 0 && (
          <span style={{ fontSize: "11px", color: COLORS.muted, padding: "5px 0" }}>No devices connected</span>
        )}
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        {[
          { label: "TOTAL ALERTS",  value: alerts.length, accent: COLORS.cyan },
          { label: "MODIFICATIONS", value: totalModified,  accent: COLORS.amber },
          { label: "DELETIONS",     value: totalDeleted,   accent: COLORS.red,  alert: true },
          { label: "NEW FILES",     value: totalNew,       accent: COLORS.blue },
        ].map(card => (
          <div key={card.label} style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: "14px", position: "relative", overflow: "hidden" }}>
            <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: card.accent }} />
            <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "10px" }}>{card.label}</div>
            <div style={{ fontSize: "26px", fontWeight: 700, fontFamily: "monospace", color: card.alert && card.value > 0 ? COLORS.red : COLORS.text }}>
              {card.value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* Middle Row: Paths + Tree Explorer */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <Card>
          <CardLabel>MONITORED PATHS {selectedDevice && `— ${selectedDevice}`}</CardLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: "5px", marginBottom: "12px" }}>
            {paths.length === 0 ? (
              <div style={{ fontSize: "12px", color: COLORS.muted }}>No paths configured</div>
            ) : paths.map((p, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px", padding: "7px 10px", background: "#060d1a", borderRadius: "6px", border: `1px solid ${COLORS.border}` }}>
                <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: COLORS.green, flexShrink: 0, display: "inline-block" }} />
                <span style={{ fontFamily: "monospace", fontSize: "11px", color: COLORS.text, flex: 1, wordBreak: "break-all" }}>{p}</span>
                <button
                  onClick={() => handleRemovePath(p)}
                  style={{ fontSize: "10px", color: COLORS.red, background: "transparent", border: "none", cursor: "pointer", opacity: 0.6, padding: "2px 4px" }}
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          <div style={{ borderTop: `1px solid ${COLORS.border}`, paddingTop: "12px" }}>
            <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "8px" }}>ADD MANUALLY</div>
            <div style={{ display: "flex", gap: "6px" }}>
              <input
                value={newPath}
                onChange={e => setNewPath(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleAddPath()}
                placeholder="/custom/path"
                style={{ flex: 1, background: "#060d1a", border: `1px solid ${COLORS.border}`, borderRadius: "6px", padding: "6px 10px", color: COLORS.text, fontSize: "12px", fontFamily: "monospace", outline: "none" }}
              />
              <button
                onClick={() => handleAddPath()}
                disabled={addPathMutation.isPending}
                style={{ padding: "6px 12px", borderRadius: "6px", border: `1px solid ${COLORS.cyan}33`, background: `${COLORS.cyan}11`, color: COLORS.cyan, fontSize: "12px", cursor: "pointer", opacity: addPathMutation.isPending ? 0.5 : 1 }}
              >
                {addPathMutation.isPending ? "..." : "Add"}
              </button>
            </div>
            {pathMsg && (
              <div style={{ fontSize: "11px", marginTop: "6px", color: pathMsg.type === "success" ? COLORS.green : COLORS.red }}>
                {pathMsg.text}
              </div>
            )}
          </div>
        </Card>

        <Card>
          <CardLabel>BROWSE & ADD PATHS</CardLabel>
          <div style={{ fontSize: "10px", color: COLORS.muted, marginBottom: "10px" }}>
            Click <span style={{ color: COLORS.cyan }}>+ Add</span> to start monitoring a path
          </div>
          <div style={{ overflow: "auto", maxHeight: "260px" }}>
            <div style={{ fontFamily: "monospace" }}>
              {PATH_TREE.map((node, i) => (
                <TreeNode key={i} node={node} depth={0} monitoredPaths={paths} onAdd={handleAddPath} />
              ))}
            </div>
          </div>
        </Card>
      </div>

      {/* Alerts Table */}
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <div style={{ display: "flex", gap: "6px" }}>
            {["ALL", "FIM_MODIFICATION", "FIM_DELETION", "FIM_NEW_FILE"].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: "4px 12px", borderRadius: "6px", fontSize: "11px", cursor: "pointer",
                  border: `1px solid ${filter === f ? COLORS.cyan + "55" : COLORS.border}`,
                  background: filter === f ? `${COLORS.cyan}11` : "transparent",
                  color: filter === f ? COLORS.cyan : COLORS.muted,
                }}
              >
                {f === "ALL" ? "All" : TYPE_META[f].label}
                <span style={{ marginLeft: "6px", fontFamily: "monospace", fontSize: "10px" }}>
                  {f === "ALL" ? alerts.length : alerts.filter(a => a.type === f).length}
                </span>
              </button>
            ))}
          </div>
          <span style={{ fontSize: "10px", color: COLORS.muted, fontFamily: "monospace" }}>
            {filteredAlerts.length} results
          </span>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
              {["TYPE", "FILE PATH", "SEVERITY", "TIME", ""].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", color: "#1a3a5a", fontWeight: 500, fontSize: "10px", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={5} style={{ padding: "24px 10px", color: COLORS.muted, textAlign: "center", fontSize: "12px" }}>
                  No alerts found
                </td>
              </tr>
            ) : filteredAlerts.map((alert, i) => {
              const meta = TYPE_META[alert.type] || { label: alert.type, color: COLORS.muted, accent: COLORS.border };
              return (
                <tr key={alert._id || i} style={{ borderBottom: `1px solid #080f1a` }}>
                  <td style={{ padding: "8px 10px" }}>
                    <span style={{ padding: "2px 8px", borderRadius: "4px", background: meta.accent, color: meta.color, border: `1px solid ${meta.color}33`, fontSize: "10px", whiteSpace: "nowrap" }}>
                      {meta.label}
                    </span>
                  </td>
                  <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.text, fontSize: "11px", maxWidth: "360px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {alert.file}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    <SeverityDot severity={alert.severity} />
                  </td>
                  <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "11px", whiteSpace: "nowrap" }}>
                    {alert.time || "—"}
                  </td>
                  <td style={{ padding: "8px 10px" }}>
                    <button
                      onClick={() => handleDeleteAlert(alert._id)}
                      style={{ fontSize: "10px", color: COLORS.red, background: "transparent", border: "none", cursor: "pointer", opacity: 0.5 }}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>
    </div>
  );
}