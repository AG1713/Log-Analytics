import { Shield, AlertTriangle, Activity, BarChart3 } from "lucide-react";
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from "recharts";
import { useEffect, useState } from "react";

export default function App() {
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    fetch("/attack_summary.json")
      .then(res => res.json())
      .then(data => setSummary(data));
  }, []);

  const chartData = summary
    ? Object.entries(summary.distribution).map(([key, value]) => ({
        name: key,
        value: value,
      }))
    : [];

  const COLORS = [
    "#ef4444",
    "#f97316",
    "#eab308",
    "#22c55e",
    "#3b82f6",
    "#a855f7",
    "#14b8a6",
    "#f43f5e",
    "#84cc16",
    "#06b6d4",
  ];

  return (
    <div className="flex h-screen">

      {/* Sidebar */}
      <div className="w-64 bg-slate-900 p-6 space-y-6">
        <h1 className="text-2xl font-bold text-blue-400">SecurePulse</h1>
        <nav className="space-y-4">
          <p className="text-slate-400 hover:text-white cursor-pointer">Dashboard</p>
          <p className="text-slate-400 hover:text-white cursor-pointer">Network Attacks</p>
          <p className="text-slate-400 hover:text-white cursor-pointer">Log Anomalies</p>
          <p className="text-slate-400 hover:text-white cursor-pointer">Reports</p>
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-8 space-y-8 overflow-auto">
        
        <h2 className="text-3xl font-bold">Security Dashboard</h2>

        {/* Cards */}
        <div className="grid grid-cols-4 gap-6">
          <Card icon={<Shield />} title="Total Records Analyzed" value={summary ? summary.total_attacks : "..."} />
          <Card icon={<AlertTriangle />} title="Critical (Worms)" value={summary ? summary.distribution.Worms : "..."} />
          <Card icon={<Activity />} title="DoS Attacks" value={summary ? summary.distribution.DoS : "..."} />
          <Card icon={<BarChart3 />} title="Normal Traffic" value={summary ? summary.distribution.Normal : "..."} />
        </div>

        {/* Chart */}
        <div className="bg-slate-900 p-6 rounded-xl">
          <h3 className="text-xl mb-4">Attack Distribution (Model Prediction)</h3>
          <ResponsiveContainer width="100%" height={400}>
            <PieChart>
              <Pie data={chartData} dataKey="value" outerRadius={150}>
                {chartData.map((entry, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

      </div>
    </div>
  );
}

function Card({ icon, title, value }) {
  return (
    <div className="bg-slate-900 p-6 rounded-xl flex justify-between items-center">
      <div>
        <p className="text-slate-400">{title}</p>
        <h3 className="text-2xl font-bold mt-2">{value}</h3>
      </div>
      <div className="text-blue-400">{icon}</div>
    </div>
  );
}