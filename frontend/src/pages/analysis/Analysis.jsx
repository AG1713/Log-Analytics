import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from "../../lib/api";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  LineChart, Line, Legend, XAxis, YAxis, CartesianGrid
} from "recharts";

// --- Constants (Matching Dashboard) ---
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
  "Port Scan":    COLORS.orange,
  Exploits:       COLORS.orange,
  Reconnaissance: COLORS.blue,
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
const Card = ({ children, style = {}, noPadding = false }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: noPadding ? 0 : "16px", ...style }}>
    {children}
  </div>
);

const CardLabel = ({ children, style = {} }) => (
  <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "12px", textTransform: "uppercase", ...style }}>
    {children}
  </div>
);

const StatCard = ({ label, value, accent, sub }) => (
  <div style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: "9px", padding: "14px", position: "relative", overflow: "hidden" }}>
    <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: "2px", background: accent }} />
    <div style={{ fontSize: "10px", color: COLORS.muted, letterSpacing: "0.07em", marginBottom: "10px" }}>{label}</div>
    <div style={{ fontSize: "26px", fontWeight: 700, fontFamily: "monospace", color: COLORS.text, marginBottom: "4px" }}>
      {typeof value === "number" ? value.toLocaleString() : value}
    </div>
    <div style={{ fontSize: "10px", color: COLORS.muted }}>{sub}</div>
  </div>
);

const AttackBadge = ({ attack }) => {
  const color = ATTACK_COLORS[attack] || COLORS.muted;
  const isAttack = attack && attack !== "BENIGN" && attack !== "Normal";
  return (
    <span style={{
      padding: "2px 6px", borderRadius: "3px", fontSize: "10px",
      background: `${color}20`, color: color, border: `1px solid ${color}40`,
      fontWeight: isAttack ? 600 : 400,
    }}>
      {attack || "—"}
    </span>
  );
};

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

const ProtoBadge = ({ proto }) => {
  const s = PROTO_STYLE[proto] || { bg: "#ffffff11", color: COLORS.muted, border: "#ffffff22" };
  return (
    <span style={{ padding: "2px 6px", borderRadius: "3px", fontSize: "10px", background: s.bg, color: s.color, border: `1px solid ${s.border}`, textTransform: "uppercase" }}>
      {proto || "—"}
    </span>
  );
};

// Helper to format timestamps nicely
const formatDate = (dateString) => {
  if (!dateString) return "N/A";
  return new Date(dateString).toLocaleString(undefined, { 
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' 
  });
};

// Make sure to pass selectedDevice as a prop from your parent component!
const AlertsTable = ({ selectedDevice }) => {
  const queryClient = useQueryClient();

  // 1. Fetch Alerts
  const { data: alerts = [], isLoading, isError, refetch, isFetching } = useQuery({
    // Add selectedDevice to the queryKey so it refetches when the tab changes
    queryKey: ['attack_alerts', selectedDevice], 
    queryFn: () => api.fetchAttackAlerts({
      // Because your cleanParams logic is so good, if selectedDevice is null ("All"), 
      // it just gets ignored!
      hostname: selectedDevice 
    }), 
  });

  // 2. Toggle Status Mutation
  const toggleMutation = useMutation({
    mutationFn: (id) => api.toggleAttackAlertStatus(id),
    onSuccess: () => {
      // Instantly refetch the alerts to show the updated status
      // (This invalidates all queries starting with 'attack_alerts', including the filtered ones)
      queryClient.invalidateQueries({ queryKey: ['attack_alerts'] });
    }
  });

  // 3. Delete Alert Mutation
  const deleteMutation = useMutation({
    mutationFn: (id) => api.deleteAttackAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['attack_alerts'] });
    }
  });

  if (isLoading) return <div style={{ padding: "40px", textAlign: "center", color: COLORS.muted }}>Loading alerts...</div>;
  if (isError) return <div style={{ padding: "40px", textAlign: "center", color: COLORS.red }}>Error loading alerts.</div>;
  if (alerts.length === 0) return <div style={{ padding: "40px", textAlign: "center", color: COLORS.muted }}>No active alerts found.</div>;

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${COLORS.border}`, color: COLORS.muted }}>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>SEVERITY</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>TYPE</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>SOURCE IP</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>TARGET IP</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>COUNT</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>CONFIDENCE</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>LAST SEEN</th>
            <th style={{ padding: "12px 16px", fontWeight: 500 }}>STATUS</th>
            <th style={{ padding: "12px 16px", fontWeight: 500, textAlign: "right" }}>ACTIONS</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => {
            const isResolved = alert.status === "Resolved";
            return (
              <tr key={alert._id} style={{ borderBottom: `1px solid ${COLORS.border}`, opacity: isResolved ? 0.6 : 1 }}>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{
                    color: alert.severity === "high" ? COLORS.red : alert.severity === "medium" ? COLORS.orange : COLORS.cyan,
                    textTransform: "uppercase", fontWeight: "bold"
                  }}>
                    {alert.severity}
                  </span>
                </td>
                <td style={{ padding: "12px 16px", color: COLORS.text }}>{alert.attack_type}</td>
                <td style={{ padding: "12px 16px", fontFamily: "monospace", color: COLORS.muted }}>{alert.src_ip}</td>
                <td style={{ padding: "12px 16px", fontFamily: "monospace", color: COLORS.muted }}>{alert.dst_ip}</td>
                <td style={{ padding: "12px 16px", color: COLORS.text }}>{alert.event_count}</td>
                <td style={{ padding: "12px 16px", color: COLORS.text }}>{(alert.avg_confidence * 100).toFixed(1)}%</td>
                <td style={{ padding: "12px 16px", color: COLORS.muted }}>{formatDate(alert.last_seen)}</td>
                <td style={{ padding: "12px 16px" }}>
                  <span style={{
                    padding: "2px 8px", borderRadius: "4px", fontSize: "10px", fontWeight: "bold", textTransform: "uppercase",
                    backgroundColor: isResolved ? "rgba(0, 255, 0, 0.1)" : "rgba(255, 0, 0, 0.1)",
                    color: isResolved ? "#4ade80" : COLORS.red
                  }}>
                    {alert.status}
                  </span>
                </td>
                <td style={{ padding: "12px 16px", textAlign: "right" }}>
                  <button 
                    onClick={() => toggleMutation.mutate(alert._id)}
                    disabled={toggleMutation.isPending}
                    style={{
                      background: "transparent", border: `1px solid ${COLORS.border}`, color: COLORS.text,
                      padding: "4px 8px", borderRadius: "4px", cursor: "pointer", marginRight: "8px", fontSize: "11px"
                    }}
                  >
                    {isResolved ? "Reopen" : "Resolve"}
                  </button>
                  <button 
                    onClick={() => deleteMutation.mutate(alert._id)}
                    disabled={deleteMutation.isPending}
                    style={{
                      background: "transparent", border: `1px solid ${COLORS.red}`, color: COLORS.red,
                      padding: "4px 8px", borderRadius: "4px", cursor: "pointer", fontSize: "11px"
                    }}
                  >
                    {deleteMutation.isPending ? "..." : "Delete"}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

// --- Main Component ---
export default function Analysis() {
  const [activeTab, setActiveTab] = useState("alerts"); // 'alerts' or 'predictions'
  const [selectedDevice, setSelectedDevice] = useState(null);
  const queryClient = useQueryClient();

  // Fetch Summary for KPIs and Pie Chart
  const { data: summary, isLoading: loadingSummary } = useQuery({
    queryKey: ["analysisSummary"],
    queryFn: api.fetchAnalysisSummary,
    refetchInterval: 30000,
  });

  // Fetch Attack Timeline
  const { data: timelineData = [] } = useQuery({
    queryKey: ["attackTimeline"],
    queryFn: () => api.fetchAttackTimeline(6),
    refetchInterval: 30000,
  });

  const { data: fetchedDevices } = useQuery({
    queryKey: ["devices"],
    queryFn: () => api.fetchDevices(),
  });
  const deviceList = Array.isArray(fetchedDevices) ? fetchedDevices : (fetchedDevices?.devices || []);

  const { data: predictionLogs = [], isLoading: isPredictionsLoading } = useQuery({
    queryKey: ["predictionLogs", selectedDevice],
    // Pass selectedDevice (or null if it represents "All")
    queryFn: () => api.fetchPredictions(50, selectedDevice === "All" ? null : selectedDevice),
    enabled: activeTab === "predictions",
    staleTime: Infinity, 
  });

  useEffect(() => {
    if (activeTab !== "predictions") return;

    const es = api.streamPredictions(selectedDevice === "All" ? null : selectedDevice);

    es.onmessage = (e) => {
      try {
        const incoming = JSON.parse(e.data);
        if (incoming.error || !Array.isArray(incoming)) return;

        // Update the React Query cache directly
        queryClient.setQueryData(["predictionLogs", selectedDevice], (oldData = []) => {
          const existingIds = new Set(oldData.map(l => l._id));
          const newOnly = incoming.filter(l => !existingIds.has(l._id));
          return [...newOnly, ...oldData].slice(0, 100);
        });
      } catch (err) {
        console.error("SSE Parse Error:", err);
      }
    };

    es.onerror = () => es.close();
    return () => es.close();
  }, [activeTab, selectedDevice, queryClient]);

  if (loadingSummary || !summary) return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontFamily: "monospace", fontSize: "13px" }}>
      LOADING ANALYSIS...
    </div>
  );

  // Prepare Data for Charts
  const attackDistData = Object.entries(summary.attack_distribution || {}).map(([name, value]) => ({
    name, value, color: ATTACK_COLORS[name] || COLORS.purple,
  }));

  return (
    <div style={{ background: COLORS.bg, color: COLORS.text, padding: "24px 28px", flex: 1, height: "100vh", overflowY: "auto" }}>

      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, color: COLORS.text, margin: "0 0 3px", letterSpacing: "-0.02em" }}>
            Threat Analysis & Predictions
          </h1>
          <p style={{ fontSize: "10px", color: COLORS.muted, margin: 0, fontFamily: "monospace", letterSpacing: "0.06em" }}>
            ML MODELS & INCIDENT RESPONSE
          </p>
        </div>
      </div>

      {/* ROW 1: Model KPIs */}
      <div className="grid grid-cols-4 gap-3 mb-4">
        <StatCard label="TOTAL ATTACKS FLAGGED" value={summary.total_attacks} accent={COLORS.red} sub="Lifetime detections" />
        <StatCard label="DoS DETECTIONS" value={summary.dos_count || 0} accent={COLORS.orange} sub="High confidence flags" />
        <StatCard label="PORT SCAN DETECTIONS" value={summary.port_scan_count || 0} accent={COLORS.purple} sub="Reconnaissance activity" />
        <StatCard label="ACTIVE INVESTIGATIONS" value={3} accent={COLORS.cyan} sub="Pending review (Placeholder)" />
      </div>

      {/* ROW 2: Charts */}
      <div className="grid gap-3 mb-5" style={{ gridTemplateColumns: "1fr 2fr" }}>
        {/* Attack Distribution Donut */}
        <Card>
          <CardLabel>ATTACK SIGNATURES</CardLabel>
          {attackDistData.length > 0 ? (
            <ResponsiveContainer width="100%" height={210} debounce={300}>
                <PieChart>
                  <Pie data={attackDistData} cx="50%" cy="50%" innerRadius={60} outerRadius={85} paddingAngle={2} dataKey="value">
                    {attackDistData.map((e, i) => <Cell key={i} fill={e.color} stroke="transparent" />)}
                  </Pie>
                  <Tooltip {...tooltipStyle} cursor={false} />
                </PieChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontSize: "11px" }}>
              No attacks recorded.
            </div>
          )}

          {/* Custom Legend underneath the Pie Chart */}
          <div style={{ display: "flex", justifyContent: "space-around", marginTop: "4px" }}>
            {attackDistData.map(item => (
              <div key={item.name} style={{ textAlign: "center" }}>
                <div style={{ fontSize: "10px", color: COLORS.muted, display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: item.color }} />
                  {item.name}
                </div>
                <div style={{ fontSize: "14px", fontWeight: "bold", fontFamily: "monospace" }}>
                  {item.value.toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Attack Timeline */}
        <Card>
          <CardLabel>THREAT TIMELINE (LAST 6H)</CardLabel>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={235} debounce={300}>
                <LineChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 9, fill: COLORS.muted }} axisLine={false} tickLine={false} interval="preserveStartEnd" />
                  <YAxis tick={{ fontSize: 10, fill: COLORS.muted }} axisLine={false} tickLine={false} />
                  <Tooltip {...tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: "10px", color: COLORS.muted }} />
                  <Line type="monotone" dataKey="DoS" stroke={ATTACK_COLORS.DoS} dot={false} strokeWidth={2} />
                  <Line type="monotone" dataKey="Port Scan" stroke={ATTACK_COLORS["Port Scan"]} dot={false} strokeWidth={2} />
                </LineChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ height: "100%", display: "flex", alignItems: "center", justifyContent: "center", color: COLORS.muted, fontSize: "11px" }}>Aggregating prediction data...</div>
          )}
        </Card>
      </div>

      {/* ROW 3: Tabs Container */}
      <div style={{ display: "flex", gap: "16px", borderBottom: `1px solid ${COLORS.border}`, marginBottom: "16px" }}>
        <button
          onClick={() => setActiveTab("alerts")}
          style={{
            background: "transparent", border: "none", padding: "0 4px 12px", cursor: "pointer", fontSize: "12px", fontWeight: 600, letterSpacing: "0.05em",
            color: activeTab === "alerts" ? COLORS.cyan : COLORS.muted,
            borderBottom: activeTab === "alerts" ? `2px solid ${COLORS.cyan}` : "2px solid transparent",
          }}
        >
          ACTIONABLE ALERTS
        </button>
        <button
          onClick={() => setActiveTab("predictions")}
          style={{
            background: "transparent", border: "none", padding: "0 4px 12px", cursor: "pointer", fontSize: "12px", fontWeight: 600, letterSpacing: "0.05em",
            color: activeTab === "predictions" ? COLORS.cyan : COLORS.muted,
            borderBottom: activeTab === "predictions" ? `2px solid ${COLORS.cyan}` : "2px solid transparent",
          }}
        >
          RAW PREDICTIONS STREAM
        </button>
      </div>

      {/* Tab Content: ALERTS */}
      {activeTab === "alerts" && (
        <Card noPadding style={{ minHeight: "300px" }}>
          
          {/* Header with Refresh Button */}
          <div style={{ 
            padding: "16px", 
            borderBottom: `1px solid ${COLORS.border}`,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center"
          }}>
            
            {/* LEFT SIDE: Title + Hostname Toggle */}
            <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
              <CardLabel style={{ margin: 0 }}>ACTIVE THREAT INVESTIGATIONS</CardLabel>
              
              <div style={{ display: "flex", background: "#080f1a", borderRadius: "4px", overflow: "hidden", border: `1px solid ${COLORS.border}` }}>
                <button
                  onClick={() => setSelectedDevice(null)}
                  style={{ 
                    padding: "4px 12px", 
                    background: !selectedDevice ? COLORS.cyan : "transparent", 
                    color: !selectedDevice ? "#000" : COLORS.muted, 
                    border: "none", 
                    fontSize: "11px", 
                    cursor: "pointer",
                    fontWeight: !selectedDevice ? "bold" : "normal"
                  }}
                >
                  All
                </button>
                
                {deviceList.map((device) => (
                  <button
                    key={device}
                    onClick={() => setSelectedDevice(device)}
                    style={{ 
                      padding: "4px 12px", 
                      background: selectedDevice === device ? COLORS.cyan : "transparent", 
                      color: selectedDevice === device ? "#000" : COLORS.muted, 
                      border: "none",
                      borderLeft: `1px solid ${COLORS.border}`,
                      fontSize: "11px", 
                      cursor: "pointer",
                      fontWeight: selectedDevice === device ? "bold" : "normal"
                    }}
                  >
                    {device}
                  </button>
                ))}
              </div>
            </div>
            
            {/* RIGHT SIDE: Refresh Button */}
            <button 
              onClick={() => queryClient.invalidateQueries({ queryKey: ['attack_alerts'] })}
              style={{
                background: "transparent", border: `1px solid ${COLORS.border}`, color: COLORS.cyan,
                padding: "4px 12px", borderRadius: "4px", cursor: "pointer", fontSize: "11px", fontWeight: "bold"
              }}
            >
              REFRESH
            </button>
          </div>

          {/* The Data Table (Passing the state down!) */}
          <AlertsTable selectedDevice={selectedDevice} />
          
        </Card>
      )}

      {/* Tab Content: PREDICTIONS */}
      {activeTab === "predictions" && (
        <Card noPadding>
          <div style={{ padding: "16px", borderBottom: `1px solid ${COLORS.border}`, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            
            {/* Left side: Title and Toggle */}
            <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
              <CardLabel style={{ margin: 0 }}>LATEST ML PREDICTIONS (LIVE)</CardLabel>
              
              {/* Hostname Segregation Toggle */}
              <div style={{ display: "flex", background: "#080f1a", borderRadius: "4px", overflow: "hidden", border: `1px solid ${COLORS.border}` }}>
                <button
                  onClick={() => setSelectedDevice(null)} // Or "All" depending on your state logic
                  style={{ 
                    padding: "4px 12px", 
                    background: !selectedDevice ? COLORS.cyan : "transparent", 
                    color: !selectedDevice ? "#000" : COLORS.muted, 
                    border: "none", 
                    fontSize: "11px", 
                    cursor: "pointer",
                    fontWeight: !selectedDevice ? "bold" : "normal"
                  }}
                >
                  All
                </button>
                {deviceList.map((device) => (
                  <button
                    key={device}
                    onClick={() => setSelectedDevice(device)}
                    style={{ 
                      padding: "4px 12px", 
                      background: selectedDevice === device ? COLORS.cyan : "transparent", 
                      color: selectedDevice === device ? "#000" : COLORS.muted, 
                      border: "none",
                      borderLeft: `1px solid ${COLORS.border}`,
                      fontSize: "11px", 
                      cursor: "pointer",
                      fontWeight: selectedDevice === device ? "bold" : "normal"
                    }}
                  >
                    {device}
                  </button>
                ))}
              </div>
            </div>

            {/* Right side: Streaming counter */}
            <span style={{ fontSize: "10px", color: COLORS.muted, fontFamily: "monospace" }}>
              {predictionLogs.length} logs · streaming
            </span>
          </div>
          
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
              {/* ... Rest of your table code stays exactly the same ... */}
              <thead>
                <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                  {["TIME", "HOSTNAME", "SRC IP", "SRC_PORT", "DST IP", "DST_PORT", "PROTO", "SERVICE", "ATTACK TYPE", "SEVERITY", "CONFIDENCE"].map(h => (
                    <th key={h} style={{ textAlign: "left", padding: "10px 16px", color: "#1a3a5a", fontWeight: 500, fontSize: "10px", letterSpacing: "0.05em" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {predictionLogs.length === 0 ? (
                  <tr>
                    <td colSpan={11} style={{ padding: "30px", textAlign: "center", color: COLORS.muted }}>
                      Waiting for incoming packets...
                    </td>
                  </tr>
                ) : (
                  predictionLogs.map((log, i) => (
                    <tr 
                      key={log._id || i} 
                      style={{ 
                        borderBottom: `1px solid #080f1a`, 
                        background: log.attack && log.attack !== "BENIGN" && log.attack !== "Normal" ? `${COLORS.red}08` : "transparent" 
                      }}
                    >
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.muted, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "—"}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.hostname || "—"}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.src_ip || "—"}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.src_port || "—"}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.text, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.dst_ip || "—"}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.cyan, fontSize: "10px", whiteSpace: "nowrap" }}>
                        {log.dst_port || "—"}
                      </td>
                      <td style={{ padding: "10px 16px" }}>
                        <ProtoBadge proto={log.proto} />
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", color: COLORS.muted, fontSize: "10px" }}>
                        {log.service && log.service !== "-" ? log.service.toUpperCase() : "—"}
                      </td>
                      <td style={{ padding: "10px 16px" }}>
                        <AttackBadge attack={log.attack_type || log.attack} />
                      </td>
                      <td style={{ padding: "10px 16px" }}>
                        <SeverityBadge severity={log.severity} />
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "monospace", fontSize: "10px", color: log.confidence >= 0.9 ? COLORS.red : log.confidence >= 0.7 ? COLORS.amber : COLORS.green }}>
                        {log.confidence != null ? `${(log.confidence * 100).toFixed(1)}%` : "—"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}