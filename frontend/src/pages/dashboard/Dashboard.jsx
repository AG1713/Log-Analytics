import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, BarChart, Bar
} from "recharts";

// --- Constants ---
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
  purple: "#8b5cf6",
  blue:   "#06b6d4",
  orange: "#f97316",
};

const ATTACK_COLORS = {
  Normal:         COLORS.green,
  BENIGN:         COLORS.green,
  DoS:            COLORS.red,
  Exploits:       COLORS.orange,
  Fuzzers:        COLORS.amber,
  Generic:        COLORS.purple,
  Reconnaissance: COLORS.blue,
  Backdoors:      "#e11d48",
  Shellcode:      "#dc2626",
  Worms:          "#ff6b35",
};

const SEVERITY_COLORS = {
  critical: COLORS.red,
  high:     COLORS.amber,
  medium:   COLORS.blue,
  low:      COLORS.green,
  normal:   COLORS.muted,
};

const PROTO_STYLE = {
  tcp:  { bg: "#06b6d422", color: "#06b6d4", border: "#06b6d433" },
  udp:  { bg: "#8b5cf622", color: "#8b5cf6", border: "#8b5cf633" },
  icmp: { bg: "#f59e0b22", color: "#f59e0b", border: "#f59e0b33" },
};

const tooltipStyle = {
  contentStyle: { background: "#0d1626", border: "1px solid #1a2d4a", borderRadius: "6px", color: "#e2f0ff", fontSize: "12px" },
  itemStyle:    { color: "#e2f0ff" },
  labelStyle:   { color: "#2a4a6a" },
  cursor:       { fill: "#ffffff08" },
};

// --- Sub-components ---
const Card = ({ children, style = {} }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: "16px", ...style }}>
    {children}
  </div>
);

const CardLabel = ({ children }) => (
  <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "12px", textTransform: "uppercase" }}>
    {children}
  </div>
);

const StatCard = ({ label, value, accent, sub, alert }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: "14px", position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: accent }} />
    <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "10px" }}>{label}</div>
    <div style={{ fontSize: "26px", fontWeight: 700, fontFamily: "monospace", color: alert ? COLORS.red : COLORS.text, marginBottom: "4px" }}>
      {typeof value === "number" ? value.toLocaleString() : value}
    </div>
    <div style={{ fontSize: "10px", color: alert ? "#ef444488" : COLORS.muted }}>{sub}</div>
  </div>
);

const SeverityBadge = ({ severity }) => (
  <span style={{
    padding: "2px 6px", borderRadius: "3px", fontSize: "10px",
    background: `${SEVERITY_COLORS[severity] || COLORS.muted}20`,
    color: SEVERITY_COLORS[severity] || COLORS.muted,
    border: `1px solid ${SEVERITY_COLORS[severity] || COLORS.muted}40`,
    textTransform: "capitalize",
  }}>
    {severity || "—"}
  </span>
);

const AttackBadge = ({ attack }) => {
  const color = ATTACK_COLORS[attack] || COLORS.muted;
  const isAttack = attack && attack !== "BENIGN" && attack !== "Normal";
  return (
    <span style={{
      padding: "2px 6px", borderRadius: "3px", fontSize: "10px",
      background: `${color}20`,
      color: color,
      border: `1px solid ${color}40`,
      fontWeight: isAttack ? 600 : 400,
    }}>
      {attack || "—"}
    </span>
  );
};

const ProtoBadge = ({ proto }) => {
  const s = PROTO_STYLE[proto] || { bg: "#ffffff11", color: COLORS.muted, border: "#ffffff22" };
  return (
    <span style={{ padding: "2px 6px", borderRadius: "3px", fontSize: "10px", background: s.bg, color: s.color, border: `1px solid ${s.border}`, textTransform: "uppercase" }}>
      {proto || "—"}
    </span>
  );
};

// --- Main Component ---
export default function Dashboard() {
  const [showNetworkLogs, setShowNetworkLogs] = useState(false);
  const [networkLogs, setNetworkLogs]         = useState([]);
  const [selectedDevice, setSelectedDevice]   = useState(null);

  // Core metrics (updated to include IPs, DoS, Port Scans)
  const { data: summary, isLoading, isError, error } = useQuery({
    queryKey:      ["attackSummary"],
    queryFn:       api.fetchAttackSummary,
    refetchInterval: 30000,
  });

  // New: Traffic Volume Timeline
  const { data: trafficData = [] } = useQuery({
    queryKey:      ["trafficTimeline"],
    queryFn:       () => api.fetchTrafficTimeline(6),
    refetchInterval: 30000,
  });

  // New: Top 5 Recent Attacks
  const { data: recentAttacks = [] } = useQuery({
    queryKey:      ["recentAttacks"],
    queryFn:       () => api.fetchRecentAttacks(5),
    refetchInterval: 15000,
  });

  // New: Top 5 Recent FIM Alerts
  const { data: recentFim = [] } = useQuery({
    queryKey:      ["recentFim"],
    queryFn:       () => api.fetchRecentFim(5),
    refetchInterval: 15000,
  });

  const { data: devicesData } = useQuery({
    queryKey:  ["devices"],
    queryFn:   api.fetchDevices,
    staleTime: 30000,
  });
  const devices = devicesData?.devices || [];

  // Initial load for live table
  const { data: initialLogs = [] } = useQuery({
    queryKey: ["networkLogs"],
    queryFn:  () => api.fetchNetworkLogs(50),
    enabled:  showNetworkLogs,
    staleTime: 0,
  });

  useEffect(() => {
    if (initialLogs.length > 0 && networkLogs.length === 0) {
      setNetworkLogs(initialLogs);
    }
  }, [initialLogs]);

  // SSE for live network logs
  useEffect(() => {
    if (!showNetworkLogs) {
      setNetworkLogs([]);
      return;
    }

    setNetworkLogs([]);
    const es = api.streamNetwork(selectedDevice);

    es.onmessage = (e) => {
      try {
        const incoming = JSON.parse(e.data);
        if (!Array.isArray(incoming) || incoming.error) return;
        setNetworkLogs(prev => {
          const existingIds = new Set(prev.map(l => l._id));
          const newOnly = incoming.filter(l => !existingIds.has(l._id));
          return [...newOnly, ...prev].slice(0, 100);
        });
      } catch {}
    };
    es.onerror = () => es.close();
    return () => es.close();
  }, [showNetworkLogs, selectedDevice]);

  if (isLoading || !summary) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontFamily: "monospace", fontSize: "13px" }}>
      LOADING DASHBOARD...
    </div>
  );

  if (isError) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.red, fontFamily: "monospace", fontSize: "13px" }}>
      ERROR: {error.message}
    </div>
  );

  // Data for Donut Chart
  const trafficSplitData = [
    { name: "Normal", value: summary.total_normal, color: COLORS.green },
    { name: "Suspicious", value: summary.total_attacks, color: COLORS.red }
  ];

  const protocolData = Object.entries(summary.protocol_distribution).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));
  
  const serviceData = Object.entries(summary.service_distribution).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));

  return (
    <div style={{ background: COLORS.bg, color: COLORS.text, padding: "24px 28px", flex: 1, height: "100vh", overflowY: "auto" }}>

      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: COLORS.text, margin: "0 0 3px", letterSpacing: "-0.02em" }}>
            Security Dashboard
          </h1>
          <p style={{ fontSize: "10px", color: COLORS.muted, margin: 0, fontFamily: "monospace", letterSpacing: "0.06em" }}>
            SYSTEM HEALTH & TRIAGE · {new Date().toUTCString()}
          </p>
        </div>
      </div>

      {/* ROW 1: Targeted Stat Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <StatCard label="TOTAL NETWORK TRAFFIC" value={summary.total_records} accent={COLORS.blue} sub="Row count in raw logs" />
        <StatCard label="UNIQUE SOURCE IPs" value={summary.unique_ips || 0} accent={COLORS.purple} sub="Distinct external hosts" />
        <StatCard label="DoS SPIKES DETECTED" value={summary.dos_count || 0} accent={COLORS.red} sub="Identified by ML model" alert={summary.dos_count > 0} />
        <StatCard label="ACTIVE PORT SCANS" value={summary.port_scan_count || 0} accent={COLORS.orange} sub="Reconnaissance attempts" alert={summary.port_scan_count > 0} />
      </div>

      {/* ROW 2: High-Level Charts */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        {/* Normal vs Suspicious Donut */}
        {/* <Card>
          <CardLabel>TRAFFIC CLASSIFICATION</CardLabel>
          <ResponsiveContainer width="100%" height={180} debounce={300}>
            <PieChart>
              <Pie data={trafficSplitData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={2} dataKey="value">
                {trafficSplitData.map((e, i) => <Cell key={i} fill={e.color} stroke="transparent" />)}
              </Pie>
              <Tooltip {...tooltipStyle} cursor={false} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", justifyContent: "space-around", marginTop: "8px" }}>
            {trafficSplitData.map(item => (
              <div key={item.name} style={{ textAlign: "center" }}>
                <div style={{ fontSize: "10px", color: COLORS.muted, display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: item.color }} />
                  {item.name}
                </div>
                <div style={{ fontSize: "14px", fontWeight: "bold", fontFamily: "monospace" }}>{item.value.toLocaleString()}</div>
              </div>
            ))}
          </div>
        </Card> */}

        {/* Traffic Volume vs Time */}
        <Card>
          <CardLabel>TRAFFIC VOLUME VS TIME (LAST 6H)</CardLabel>
          <ResponsiveContainer width="100%" height={210} debounce={300}>
            {trafficData.length > 0 ? (
              <LineChart data={trafficData}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: COLORS.muted }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
                <Tooltip {...tooltipStyle} />
                <Line type="monotone" dataKey="traffic" stroke={COLORS.cyan} dot={false} strokeWidth={2} name="Volume" />
              </LineChart>
            ) : (
              <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontSize: "11px" }}>
                Aggregating network data...
              </div>
            )}
          </ResponsiveContainer>
        </Card>
        
        <Card style={{ display: "flex", flexDirection: "column" }}>
          <CardLabel>LOGS BY PROTOCOL</CardLabel>
          <div style={{ flex: 1, minHeight: 0 }}>
            <ResponsiveContainer width="100%" height="100%" debounce={300}>
              <BarChart data={protocolData} layout="vertical" barSize={12}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} width={36} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="value" name="Count" fill={COLORS.blue} radius={[0, 3, 3, 0]} opacity={0.85} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card style={{ display: "flex", flexDirection: "column" }}>
          <CardLabel>LOGS BY SERVICE</CardLabel>
          <div style={{ flex: 1, minHeight: 0 }}>
            <ResponsiveContainer width="100%" height="100%" debounce={300}>
              <BarChart data={serviceData} layout="vertical" barSize={12}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} horizontal={false} />
                <XAxis type="number" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} width={40} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="value" name="Count" fill={COLORS.purple} radius={[0, 3, 3, 0]} opacity={0.85} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

      </div>

      {/* ROW 3: Quick Triage Alerts */}
      <div className="grid gap-3 mb-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
        {/* Attack Alerts List */}
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <CardLabel style={{ margin: 0 }}>RECENT ATTACK ALERTS</CardLabel>
            <button 
              onClick={() => window.location.href = '/analysis'} 
              style={{ fontSize: "10px", color: COLORS.cyan, background: "transparent", border: "none", cursor: "pointer" }}
            >
              View Analysis &rarr;
            </button>
          </div>
          <div>
            {recentAttacks.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: COLORS.muted, fontSize: "11px" }}>No recent attacks detected.</div>
            ) : recentAttacks.map((alert, i) => (
              <div key={i} style={{ padding: "10px 16px", borderBottom: i < 4 ? `1px solid ${COLORS.border}` : "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ fontSize: "12px", color: COLORS.text, marginBottom: "2px" }}>{alert.src_ip} &rarr; {alert.dst_ip}</div>
                  <div style={{ fontSize: "10px", color: COLORS.muted, fontFamily: "monospace" }}>{alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "—"}</div>
                </div>
                <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                  <SeverityBadge severity={alert.severity} />
                  <AttackBadge attack={alert.attack} />
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* FIM Alerts List */}
        <Card style={{ padding: 0, overflow: "hidden" }}>
          <div style={{ padding: "12px 16px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <CardLabel style={{ margin: 0 }}>RECENT FIM ALERTS</CardLabel>
            <button 
              onClick={() => window.location.href = '/fim'} 
              style={{ fontSize: "10px", color: COLORS.cyan, background: "transparent", border: "none", cursor: "pointer" }}
            >
              View FIM Dashboard &rarr;
            </button>
          </div>
          <div>
            {recentFim.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: COLORS.muted, fontSize: "11px" }}>No recent file integrity alerts.</div>
            ) : recentFim.map((alert, i) => (
              <div key={i} style={{ padding: "10px 16px", borderBottom: i < 4 ? `1px solid ${COLORS.border}` : "none", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "70%" }}>
                  <div style={{ fontSize: "12px", color: COLORS.text, marginBottom: "2px", overflow: "hidden", textOverflow: "ellipsis" }}>{alert.file}</div>
                  <div style={{ fontSize: "10px", color: COLORS.muted, fontFamily: "monospace" }}>{alert.hostname} • {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "—"}</div>
                </div>
                <span style={{ fontSize: "10px", padding: "2px 6px", background: `${COLORS.amber}20`, color: COLORS.amber, borderRadius: "3px", border: `1px solid ${COLORS.amber}40` }}>
                  {alert.type || "MODIFIED"}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* ROW 4: Network Logs Toggle & Table (Unchanged logic, just UI fit) */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", marginTop: "16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <button
            onClick={() => setShowNetworkLogs(v => !v)}
            style={{
              display: "flex", alignItems: "center", gap: "8px",
              padding: "6px 14px", borderRadius: "6px", cursor: "pointer",
              border: `1px solid ${showNetworkLogs ? COLORS.cyan + "55" : COLORS.border}`,
              background: showNetworkLogs ? `${COLORS.cyan}11` : "transparent",
              color: showNetworkLogs ? COLORS.cyan : COLORS.muted,
              fontSize: "12px",
            }}
          >
            <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: showNetworkLogs ? COLORS.green : COLORS.muted, display: "inline-block" }} />
            {showNetworkLogs ? "Live Network Traffic — ON" : "Live Network Traffic — OFF"}
          </button>

          {showNetworkLogs && (
            <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
              <button
                onClick={() => setSelectedDevice(null)}
                style={{
                  padding: "4px 10px", borderRadius: "5px", fontSize: "11px", cursor: "pointer",
                  border: `1px solid ${!selectedDevice ? COLORS.cyan + "55" : COLORS.border}`,
                  background: !selectedDevice ? `${COLORS.cyan}11` : "transparent",
                  color: !selectedDevice ? COLORS.cyan : COLORS.muted,
                }}
              >
                All
              </button>
              {devices.map(d => (
                <button
                  key={d}
                  onClick={() => setSelectedDevice(d)}
                  style={{
                    padding: "4px 10px", borderRadius: "5px", fontSize: "11px", cursor: "pointer",
                    fontFamily: "monospace",
                    border: `1px solid ${selectedDevice === d ? COLORS.cyan + "55" : COLORS.border}`,
                    background: selectedDevice === d ? `${COLORS.cyan}11` : "transparent",
                    color: selectedDevice === d ? COLORS.cyan : COLORS.muted,
                  }}
                >
                  {d}
                </button>
              ))}
            </div>
          )}
        </div>

        {showNetworkLogs && (
          <span style={{ fontSize: "10px", color: COLORS.muted, fontFamily: "monospace" }}>
            {networkLogs.length} packets · streaming
          </span>
        )}
      </div>

      {showNetworkLogs && (
        <Card>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
            <thead>
              <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                {["TIME", "HOSTNAME", "SRC IP", "SRC_PORT", "DST IP", "DST_PORT", "PROTO", "SERVICE", "ATTACK TYPE", "SEVERITY", "CONFIDENCE"].map(h => (
                  <th key={h} style={{ textAlign: "left", padding: "6px 10px", color: "#1a3a5a", fontWeight: 500, fontSize: "10px", letterSpacing: "0.05em" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {networkLogs.length === 0 ? (
                <tr>
                  <td colSpan={11} style={{ padding: "24px 10px", color: COLORS.muted, textAlign: "center", fontSize: "12px" }}>
                    Waiting for packets...
                  </td>
                </tr>
              ) : networkLogs.map((log, i) => (
                <tr
                  key={log._id || i}
                  style={{
                    borderBottom: `1px solid #080f1a`,
                    background: log.attack && log.attack !== "BENIGN" && log.attack !== "Normal"
                      ? `${COLORS.red}08`
                      : "transparent",
                  }}
                >
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "—"}
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.hostname || "—"}
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.src_ip || "—"}
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.src_port || "—"}
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.text, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.dst_ip || "—"}
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                    {log.dst_port || "—"}
                  </td>
                  <td style={{ padding: "7px 10px" }}>
                    <ProtoBadge proto={log.proto} />
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "10px" }}>
                    {log.service && log.service !== "-" ? log.service.toUpperCase() : "—"}
                  </td>
                  <td style={{ padding: "7px 10px" }}>
                    <AttackBadge attack={log.attack_type} />
                  </td>
                  <td style={{ padding: "7px 10px" }}>
                    <SeverityBadge severity={log.severity} />
                  </td>
                  <td style={{ padding: "7px 10px", fontFamily: "monospace", fontSize: "10px", color: log.confidence >= 0.9 ? COLORS.red : log.confidence >= 0.7 ? COLORS.amber : COLORS.green }}>
                    {log.confidence != null ? `${(log.confidence * 100).toFixed(1)}%` : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}