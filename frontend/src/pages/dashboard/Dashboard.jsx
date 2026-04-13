import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../lib/api";
import {
  PieChart, Pie, Cell, Tooltip, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer,
  LineChart, Line, Legend,
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
  <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "12px" }}>
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

  // Summary cards + charts — refresh every 30s
  const { data, isLoading, isError, error } = useQuery({
    queryKey:      ["attackSummary"],
    queryFn:       api.fetchAttackSummary,
    refetchInterval: 30000,
  });

  // Attack timeline for the line chart — refresh every 30s
  const { data: timelineData = [] } = useQuery({
    queryKey:      ["attackTimeline"],
    queryFn:       () => api.fetchAttackTimeline(6),
    refetchInterval: 30000,
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
    enabled:  showNetworkLogs,    // only fetch when table is open
    staleTime: 0,
  });

  // Seed table with initial logs when they arrive
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

  if (isLoading || !data) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontFamily: "monospace", fontSize: "13px" }}>
      LOADING...
    </div>
  );

  if (isError) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.red, fontFamily: "monospace", fontSize: "13px" }}>
      ERROR: {error.message}
    </div>
  );

  // Transform API data for charts
  const attackDistData = Object.entries(data.attack_distribution).map(([name, value]) => ({
    name, value, color: ATTACK_COLORS[name] || COLORS.muted,
  }));

  const severityData = Object.entries(data.severity_distribution)
    .filter(([k]) => k !== "normal")
    .map(([name, value]) => ({ name, value, color: SEVERITY_COLORS[name] }));

  const protocolData = Object.entries(data.protocol_distribution).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));

  const serviceData = Object.entries(data.service_distribution).map(([name, value]) => ({
    name: name.toUpperCase(), value,
  }));

  const attackRate    = ((data.total_attacks / data.total_records) * 100).toFixed(1);
  const criticalCount = data.severity_distribution?.critical || 0;

  return (
    <div style={{ background: COLORS.bg, color: COLORS.text, padding: "24px 28px", flex: 1 }}>

      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: COLORS.text, margin: "0 0 3px", letterSpacing: "-0.02em" }}>
            Security Dashboard
          </h1>
          <p style={{ fontSize: "10px", color: COLORS.muted, margin: 0, fontFamily: "monospace", letterSpacing: "0.06em" }}>
            LIVE · {new Date().toUTCString()}
          </p>
        </div>
        <button style={{ padding: "5px 14px", borderRadius: "6px", border: `1px solid ${COLORS.cyan}33`, background: `${COLORS.cyan}11`, fontSize: "12px", color: COLORS.cyan, cursor: "pointer" }}>
          Export
        </button>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <StatCard label="TOTAL RECORDS"   value={data.total_records}  accent={COLORS.blue}   sub="From live dataset" />
        <StatCard label="TOTAL ATTACKS"   value={data.total_attacks}  accent={COLORS.red}    sub={`${attackRate}% of total traffic`} alert />
        <StatCard label="CRITICAL EVENTS" value={criticalCount}       accent={COLORS.orange} sub="Worms, Backdoors, Shellcode" alert />
        <StatCard label="NORMAL TRAFFIC"  value={data.total_normal}   accent={COLORS.green}  sub={`${(100 - parseFloat(attackRate)).toFixed(1)}% of total`} />
      </div>

      {/* Severity Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        {["critical", "high", "medium", "low"].map(sev => (
          <div key={sev} style={{ background: `${SEVERITY_COLORS[sev]}0d`, border: `1px solid ${SEVERITY_COLORS[sev]}30`, borderRadius: "9px", padding: "12px 14px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: "11px", color: SEVERITY_COLORS[sev], textTransform: "uppercase", letterSpacing: "0.06em" }}>{sev}</span>
            <span style={{ fontSize: "20px", fontWeight: 700, fontFamily: "monospace", color: SEVERITY_COLORS[sev] }}>
              {(data.severity_distribution?.[sev] || 0).toLocaleString()}
            </span>
          </div>
        ))}
      </div>

      {/* Charts Row 1 */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        <Card>
          <CardLabel>ATTACK DISTRIBUTION</CardLabel>
          <ResponsiveContainer width="100%" height={180} debounce={300}>
            <PieChart>
              <Pie data={attackDistData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={2} dataKey="value">
                {attackDistData.map((e, i) => <Cell key={i} fill={e.color} stroke="transparent" />)}
              </Pie>
              <Tooltip {...tooltipStyle} cursor={false} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "5px", marginTop: "8px" }}>
            {attackDistData.map(item => (
              <div key={item.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "10px" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "4px", color: "#4a6a8a" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "2px", background: item.color, display: "inline-block", flexShrink: 0 }} />
                  {item.name}
                </span>
                <span style={{ fontFamily: "monospace", color: COLORS.text }}>{item.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
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

      {/* Charts Row 2 */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 2fr" }}>

        {/* ✅ REPLACED: Connection State → Attack Timeline */}
        <Card>
          <CardLabel>ATTACK TIMELINE · LAST 6H</CardLabel>
          <ResponsiveContainer width="100%" height={160} debounce={300}>
            {timelineData.length > 0 ? (
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
                <XAxis dataKey="time" tick={{ fontSize: 9, fill: COLORS.muted }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
                <Tooltip {...tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: "10px", color: COLORS.muted }} />
                <Line type="monotone" dataKey="attacks" stroke={COLORS.red}   dot={false} strokeWidth={1.5} name="Attacks" />
                <Line type="monotone" dataKey="normal"  stroke={COLORS.green} dot={false} strokeWidth={1.5} name="Normal"  />
              </LineChart>
            ) : (
              <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontSize: "11px" }}>
                Collecting data...
              </div>
            )}
          </ResponsiveContainer>
        </Card>

        <Card>
          <CardLabel>SEVERITY BREAKDOWN</CardLabel>
          <ResponsiveContainer width="100%" height={160} debounce={300}>
            <BarChart data={severityData} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="value" name="Count" radius={[3, 3, 0, 0]} opacity={0.85}>
                {severityData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Network Logs Toggle Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", marginTop: "4px" }}>
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

      {/* Network Logs Table — updated columns for predictions schema */}
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
                    // highlight attack rows subtly
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