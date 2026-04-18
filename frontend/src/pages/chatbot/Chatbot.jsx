import { useState } from "react";

const COLORS = {
  bg:     "#060d1a",
  card:   "#0d1626",
  border: "#0f1e36",
  text:   "#e2f0ff",
  muted:  "#2a4a6a",
  cyan:   "#00d4ff",
  green:  "#10b981",
  red:    "#ef4444",
};

export default function Chatbot() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);

  const handleSearch = async () => {
    if (!query.trim()) return;

    setLoading(true);
    setData(null);

    try {
      const res = await fetch("http://localhost:8000/api/chatbot/query", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ query }),
      });

      const json = await res.json();
      setData(json);
    } catch (err) {
      console.error(err);
      setData({ error: "Failed to fetch" });
    }

    setLoading(false);
  };

  return (
    <div style={{ background: COLORS.bg, minHeight: "100vh", padding: "24px" }}>
      
      {/* HEADER */}
      <h1 style={{
        color: COLORS.text,
        fontSize: "20px",
        fontWeight: "bold",
        marginBottom: "12px"
      }}>
        AI Security Chatbot
      </h1>

      {/* INPUT */}
      <div style={{
        display: "flex",
        gap: "10px",
        marginBottom: "16px"
      }}>
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="e.g. show dos attacks last 1 hour"
          style={{
            flex: 1,
            padding: "10px",
            borderRadius: "6px",
            border: `1px solid ${COLORS.border}`,
            background: COLORS.card,
            color: COLORS.text,
            outline: "none"
          }}
        />

        <button
          onClick={handleSearch}
          style={{
            padding: "10px 16px",
            background: COLORS.cyan,
            color: "#000",
            border: "none",
            borderRadius: "6px",
            cursor: "pointer",
            fontWeight: "bold"
          }}
        >
          Search
        </button>
      </div>

      {/* LOADING */}
      {loading && (
        <div style={{ color: COLORS.muted }}>Processing query...</div>
      )}

      {/* ERROR */}
      {data?.error && (
        <div style={{ color: COLORS.red }}>{data.error}</div>
      )}

      {/* RESULTS */}
      {data && !loading && !data.error && (
        <div style={{
          background: COLORS.card,
          border: `1px solid ${COLORS.border}`,
          borderRadius: "8px",
          padding: "16px"
        }}>
          
          {/* FILTER INFO */}
          <div style={{
            fontSize: "12px",
            color: COLORS.muted,
            marginBottom: "10px"
          }}>
            Filters: {JSON.stringify(data.filters)}
          </div>

          <div style={{
            fontSize: "12px",
            marginBottom: "10px",
            color: COLORS.text
          }}>
            Results: {data.count}
          </div>

          {/* TABLE */}
          {data.results.length > 0 ? (
            <table style={{ width: "100%", fontSize: "12px" }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                  {["Time", "Attack", "Prediction", "Severity", "Src IP", "Dst IP"].map(h => (
                    <th key={h} style={{
                      textAlign: "left",
                      padding: "8px",
                      color: COLORS.muted
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {data.results.map((row, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid #08121f" }}>
                    <td style={{ padding: "8px", color: COLORS.muted }}>{row.time}</td>
                    <td style={{ padding: "8px", color: COLORS.red }}>{row.attack_type}</td>
                    <td style={{ padding: "8px", color: COLORS.text }}>{row.prediction}</td>
                    <td style={{ padding: "8px", color: COLORS.cyan }}>{row.severity}</td>
                    <td style={{ padding: "8px", color: COLORS.text }}>{row.src_ip}</td>
                    <td style={{ padding: "8px", color: COLORS.text }}>{row.dst_ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{ color: COLORS.muted }}>
              No results found
            </div>
          )}
        </div>
      )}
    </div>
  );
}