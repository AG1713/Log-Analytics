import { useEffect, useState } from "react";
import {
  PieChart, Pie, Cell, Tooltip, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, ResponsiveContainer
} from "recharts";

// --- Constants ---
const COLORS = {
  bg:       "#060d1a",
  card:     "#0d1626",
  border:   "#0f1e36",
  text:     "#e2f0ff",
  muted:    "#2a4a6a",
  cyan:     "#00d4ff",
  green:    "#10b981",
  red:      "#ef4444",
  amber:    "#f59e0b",
  purple:   "#8b5cf6",
  blue:     "#06b6d4",
  orange:   "#f97316",
};

const ATTACK_COLORS = {
  Normal:         COLORS.green,
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

const tooltipStyle = {
  contentStyle: {
    background: "#0d1626",
    border: "1px solid #1a2d4a",
    borderRadius: "6px",
    color: "#e2f0ff",
    fontSize: "12px",
  },
};

// --- Sub-components ---
const Card = ({ children, style = {} }) => (
  <div style={{
    background: COLORS.card,
    border: `1px solid ${COLORS.border}`,
    borderRadius: "9px",
    padding: "16px",
    ...style,
  }}>
    {children}
  </div>
);

const CardLabel = ({ children }) => (
  <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "12px" }}>
    {children}
  </div>
);

const StatCard = ({ label, value, accent, sub, alert }) => (
  <div style={{
    background: COLORS.card,
    border: `1px solid ${COLORS.border}`,
    borderRadius: "9px",
    padding: "14px",
    position: "relative",
    overflow: "hidden",
  }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: accent }} />
    <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "10px" }}>{label}</div>
    <div style={{ fontSize: "26px", fontWeight: 700, fontFamily: "monospace", color: alert ? COLORS.red : COLORS.text, marginBottom: "4px" }}>
      {typeof value === "number" ? value.toLocaleString() : value}
    </div>
    <div style={{ fontSize: "10px", color: alert ? "#ef444488" : COLORS.muted }}>{sub}</div>
  </div>
);

const SeverityDot = ({ severity }) => (
  <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
    <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: SEVERITY_COLORS[severity] || COLORS.muted, display: "inline-block" }} />
    <span style={{ color: SEVERITY_COLORS[severity] || COLORS.muted, textTransform: "capitalize", fontSize: "11px" }}>{severity}</span>
  </span>
);

// --- Main Component ---
export default function Dashboard() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("http://localhost:8000/attack_summary")
      .then(res => {
        if (!res.ok) throw new Error("Failed to fetch");
        return res.json();
      })
      .then(json => { setData(json); setLoading(false); })
      .catch(err => { setError(err.message); setLoading(false); });
  }, []);

  if (loading) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontFamily: "monospace", fontSize: "13px" }}>
      LOADING...
    </div>
  );

  if (error) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.red, fontFamily: "monospace", fontSize: "13px" }}>
      ERROR: {error}
    </div>
  );

  // --- Transform API data for charts ---
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

  const stateData = Object.entries(data.state_distribution).map(([name, value]) => ({
    name, value,
  }));

  const attackRate = ((data.total_attacks / data.total_records) * 100).toFixed(1);
  const criticalCount = data.severity_distribution?.critical || 0;
  const wormCount = data.attack_distribution?.Worms || 0;

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
        <StatCard label="TOTAL RECORDS"  value={data.total_records}  accent={COLORS.blue}   sub="From testing dataset" />
        <StatCard label="TOTAL ATTACKS"  value={data.total_attacks}  accent={COLORS.red}    sub={`${attackRate}% of total traffic`} alert />
        <StatCard label="CRITICAL EVENTS" value={criticalCount}      accent={COLORS.orange} sub="Worms, Backdoors, Shellcode" alert />
        <StatCard label="NORMAL TRAFFIC" value={data.total_normal}   accent={COLORS.green}  sub={`${(100 - parseFloat(attackRate)).toFixed(1)}% of total`} />
      </div>

      {/* Severity Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        {["critical", "high", "medium", "low"].map(sev => (
          <div key={sev} style={{
            background: `${SEVERITY_COLORS[sev]}0d`,
            border: `1px solid ${SEVERITY_COLORS[sev]}30`,
            borderRadius: "9px",
            padding: "12px 14px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}>
            <span style={{ fontSize: "11px", color: SEVERITY_COLORS[sev], textTransform: "uppercase", letterSpacing: "0.06em" }}>{sev}</span>
            <span style={{ fontSize: "20px", fontWeight: 700, fontFamily: "monospace", color: SEVERITY_COLORS[sev] }}>
              {(data.severity_distribution?.[sev] || 0).toLocaleString()}
            </span>
          </div>
        ))}
      </div>

      {/* Charts Row 1: Donut + Protocol + Service */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>

        {/* Attack Distribution Donut */}
        <Card>
          <CardLabel>ATTACK DISTRIBUTION</CardLabel>
          <ResponsiveContainer width="100%" height={180} debounce={200}>
            <PieChart>
              <Pie data={attackDistData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={2} dataKey="value">
                {attackDistData.map((e, i) => <Cell key={i} fill={e.color} stroke="transparent" />)}
              </Pie>
              <Tooltip {...tooltipStyle} />
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

        {/* Protocol Distribution */}
        <Card style={{ display: "flex", flexDirection: "column" }}>
          <CardLabel>ATTACKS BY PROTOCOL</CardLabel>
          <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%" debounce={200}>
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

        {/* Service Distribution */}
        <Card style={{ display: "flex", flexDirection: "column" }}>
          <CardLabel>ATTACKS BY SERVICE</CardLabel>
          <div style={{ flex: 1, minHeight: 0 }}>
          <ResponsiveContainer width="100%" height="100%" debounce={200}>
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

      {/* Charts Row 2: State distribution */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 2fr" }}>

        {/* State Distribution */}
        <Card>
          <CardLabel>CONNECTION STATE</CardLabel>
          <ResponsiveContainer width="100%" height={160} debounce={200}>
            <BarChart data={stateData} barSize={24}>
              <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="value" name="Count" fill={COLORS.amber} radius={[3, 3, 0, 0]} opacity={0.85} />
            </BarChart>
          </ResponsiveContainer>
        </Card>

        {/* Severity Bar */}
        <Card>
          <CardLabel>SEVERITY BREAKDOWN</CardLabel>
          <ResponsiveContainer width="100%" height={160} debounce={200}>
            <BarChart data={severityData} barSize={36}>
              <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
              <XAxis dataKey="name" tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="value" name="Count" radius={[3, 3, 0, 0]} opacity={0.85}>
                {severityData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Recent Alerts Table */}
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <CardLabel>RECENT ALERTS</CardLabel>
          <span style={{ fontSize: "11px", color: COLORS.cyan, cursor: "pointer" }}>View all →</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
              {["TYPE", "SEVERITY", "PROTOCOL", "SERVICE", "STATE", "SRC BYTES", "DST BYTES", "DURATION"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", color: "#1a3a5a", fontWeight: 500, fontSize: "10px", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.recent_alerts.map((alert, i) => (
              <tr key={i} style={{ borderBottom: `1px solid #080f1a` }}>
                <td style={{ padding: "8px 10px", color: COLORS.text, fontWeight: 600 }}>{alert.type}</td>
                <td style={{ padding: "8px 10px" }}><SeverityDot severity={alert.severity} /></td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.blue, fontSize: "11px", textTransform: "uppercase" }}>{alert.proto}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "11px" }}>{alert.service === "-" ? "—" : alert.service}</td>
                <td style={{ padding: "8px 10px" }}>
                  <span style={{ padding: "2px 7px", borderRadius: "3px", background: "#06b6d415", color: COLORS.blue, border: "1px solid #06b6d430", fontSize: "10px" }}>
                    {alert.state}
                  </span>
                </td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "11px" }}>{alert.sbytes.toLocaleString()}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "11px" }}>{alert.dbytes.toLocaleString()}</td>
                <td style={{ padding: "8px 10px", fontFamily: "monospace", color: COLORS.muted, fontSize: "11px" }}>{alert.duration}s</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

    </div>
  );
}