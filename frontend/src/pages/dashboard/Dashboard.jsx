import { PieChart, Pie, Cell, Tooltip, BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer } from "recharts";

const attackData = [
  { name: "Normal",  value: 25141, color: "#10b981" },
  { name: "DoS",     value: 3355,  color: "#ef4444" },
  { name: "Probe",   value: 2489,  color: "#f59e0b" },
  { name: "R2L",     value: 1402,  color: "#8b5cf6" },
  { name: "U2R",     value: 901,   color: "#06b6d4" },
  { name: "Worms",   value: 44,    color: "#ff6b35" },
];

const timelineData = [
  { time: "00:00", normal: 420, attack: 32 },
  { time: "04:00", normal: 310, attack: 18 },
  { time: "08:00", normal: 680, attack: 95 },
  { time: "12:00", normal: 920, attack: 142 },
  { time: "16:00", normal: 840, attack: 88 },
  { time: "20:00", normal: 560, attack: 61 },
];

const recentAlerts = [
  { type: "DoS",   source: "192.168.1.45",  severity: "critical",     time: "02:13:45", status: "Active" },
  { type: "Probe", source: "10.0.0.112",    severity: "medium",       time: "02:11:22", status: "Blocked" },
  { type: "Worm",  source: "172.16.0.88",   severity: "critical",     time: "02:09:17", status: "Active" },
  { type: "R2L",   source: "192.168.2.201", severity: "high",         time: "02:07:51", status: "Investigating" },
  { type: "DoS",   source: "10.0.1.55",     severity: "high",         time: "02:05:33", status: "Blocked" },
];

const severityColor = { critical: "#ef4444", high: "#f59e0b", medium: "#06b6d4", low: "#10b981" };
const statusStyle = {
  Active:        { bg: "#ef444415", text: "#ef4444", border: "#ef444430" },
  Blocked:       { bg: "#10b98115", text: "#10b981", border: "#10b98130" },
  Investigating: { bg: "#f59e0b15", text: "#f59e0b", border: "#f59e0b30" },
};

const tooltipStyle = {
  contentStyle: { background: "#0d1626", border: "1px solid #1a2d4a", borderRadius: "6px", color: "#e2f0ff", fontSize: "12px" },
};

export default function Dashboard() {
  return (
    <div className="flex-1 overflow-auto p-7" style={{ background: "#060d1a", color: "#e2f0ff", minHeight: "100vh" }}>
      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: "#e2f0ff", margin: "0 0 3px", letterSpacing: "-0.02em" }}>
            Security Dashboard
          </h1>
          <p style={{ fontSize: "10px", color: "#2a4a6a", margin: 0, fontFamily: "monospace", letterSpacing: "0.06em" }}>
            LIVE · {new Date().toUTCString()}
          </p>
        </div>
        <button style={{ padding: "5px 14px", borderRadius: "6px", border: "1px solid #00d4ff33", background: "#00d4ff11", fontSize: "12px", color: "#00d4ff", cursor: "pointer" }}>
          Export
        </button>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        {[
          { label: "TOTAL RECORDS",    value: "82,332", accent: "#06b6d4", sub: "+2.4% from yesterday" },
          { label: "CRITICAL (WORMS)", value: "44",     accent: "#ef4444", sub: "↑ 8 new in last hour", alert: true },
          { label: "DOS ATTACKS",      value: "3,355",  accent: "#f59e0b", sub: "Peak: 12:00–16:00" },
          { label: "NORMAL TRAFFIC",   value: "25,141", accent: "#10b981", sub: "30.5% of total" },
        ].map(card => (
          <div key={card.label} style={{ background: "#0d1626", border: "1px solid #0f1e36", borderRadius: "9px", padding: "14px", position: "relative", overflow: "hidden" }}>
            <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: card.accent }} />
            <div style={{ fontSize: "10px", color: "#2a4a6a", letterSpacing: "0.07em", marginBottom: "10px" }}>{card.label}</div>
            <div style={{ fontSize: "26px", fontWeight: 700, fontFamily: "monospace", color: card.alert ? "#ef4444" : "#e2f0ff", marginBottom: "4px" }}>
              {card.value}
            </div>
            <div style={{ fontSize: "10px", color: card.alert ? "#ef444488" : "#2a4a6a" }}>{card.sub}</div>
          </div>
        ))}
      </div>

      {/* Charts Row */}
      <div className="grid gap-3 mb-3" style={{ gridTemplateColumns: "1fr 1.8fr" }}>
        {/* Donut + Legend */}
        <div style={{ background: "#0d1626", border: "1px solid #0f1e36", borderRadius: "9px", padding: "16px" }}>
          <div style={{ fontSize: "10px", color: "#2a4a6a", letterSpacing: "0.07em", marginBottom: "10px" }}>ATTACK DISTRIBUTION</div>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={attackData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={2} dataKey="value">
                {attackData.map((e, i) => <Cell key={i} fill={e.color} stroke="transparent" />)}
              </Pie>
              <Tooltip {...tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "5px", marginTop: "8px" }}>
            {attackData.map(item => (
              <div key={item.name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", fontSize: "11px" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "5px", color: "#4a6a8a" }}>
                  <span style={{ width: "7px", height: "7px", borderRadius: "2px", background: item.color, display: "inline-block" }} />
                  {item.name}
                </span>
                <span style={{ fontFamily: "monospace", color: "#e2f0ff" }}>{item.value.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bar Chart */}
        <div style={{ background: "#0d1626", border: "1px solid #0f1e36", borderRadius: "9px", padding: "16px" }}>
          <div style={{ fontSize: "10px", color: "#2a4a6a", letterSpacing: "0.07em", marginBottom: "10px" }}>TRAFFIC TIMELINE</div>
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={timelineData} barGap={4}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0f1e36" vertical={false} />
              <XAxis dataKey="time" tick={{ fontSize: 11, fill: "#2a4a6a" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#2a4a6a" }} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} />
              <Bar dataKey="normal" name="Normal" fill="#10b981" radius={[3, 3, 0, 0]} opacity={0.8} />
              <Bar dataKey="attack" name="Attack" fill="#ef4444" radius={[3, 3, 0, 0]} opacity={0.8} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Alerts Table */}
      <div style={{ background: "#0d1626", border: "1px solid #0f1e36", borderRadius: "9px", padding: "16px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <span style={{ fontSize: "10px", color: "#2a4a6a", letterSpacing: "0.07em" }}>RECENT ALERTS</span>
          <span style={{ fontSize: "11px", color: "#00d4ff", cursor: "pointer" }}>View all →</span>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #0f1e36" }}>
              {["TYPE", "SOURCE IP", "SEVERITY", "TIME", "STATUS"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px", color: "#1a3a5a", fontWeight: 500, fontSize: "10px", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {recentAlerts.map((alert, i) => {
              const s = statusStyle[alert.status];
              return (
                <tr key={i} style={{ borderBottom: "1px solid #080f1a" }}>
                  <td style={{ padding: "9px 10px", color: "#e2f0ff", fontWeight: 500 }}>{alert.type}</td>
                  <td style={{ padding: "9px 10px", fontFamily: "monospace", color: "#06b6d4", fontSize: "11px" }}>{alert.source}</td>
                  <td style={{ padding: "9px 10px" }}>
                    <span style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                      <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: severityColor[alert.severity], display: "inline-block" }} />
                      <span style={{ color: severityColor[alert.severity], textTransform: "capitalize" }}>{alert.severity}</span>
                    </span>
                  </td>
                  <td style={{ padding: "9px 10px", fontFamily: "monospace", color: "#2a4a6a", fontSize: "11px" }}>{alert.time}</td>
                  <td style={{ padding: "9px 10px" }}>
                    <span style={{ padding: "2px 8px", borderRadius: "4px", background: s.bg, color: s.text, border: `1px solid ${s.border}`, fontSize: "11px" }}>
                      {alert.status}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}