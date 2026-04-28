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
  amber:  "#f59e0b",
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
      setData({ error: "Failed to connect to backend" });
    }

    setLoading(false);
  };

  return (
    <div style={{
      background: COLORS.bg,
      minHeight: "100vh",
      padding: "24px",
      color: COLORS.text
    }}>

      {/* HEADER */}
      <div style={{ marginBottom: "18px" }}>
        <h1 style={{
          fontSize: "20px",
          fontWeight: "bold",
          marginBottom: "4px"
        }}>
          AI Security Chatbot
        </h1>
        <p style={{
          fontSize: "11px",
          color: COLORS.muted,
          fontFamily: "monospace"
        }}>
          Query your network logs using natural language
        </p>
      </div>

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
            outline: "none",
            fontSize: "12px"
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
            fontWeight: "bold",
            fontSize: "12px"
          }}
        >
          Search
        </button>
      </div>

      {/* QUICK SUGGESTIONS */}
      {!data && !loading && (
        <div style={{
          fontSize: "11px",
          color: COLORS.muted,
          marginBottom: "12px"
        }}>
          Try:
          <div style={{ marginTop: "6px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {[
              "show dos attacks last 1 hour",
              "show high severity attacks",
              "any portscan attacks?",
              "show normal traffic last 10 minutes"
            ].map((q, i) => (
              <button
                key={i}
                onClick={() => setQuery(q)}
                style={{
                  background: "#0a1a2f",
                  border: `1px solid ${COLORS.border}`,
                  color: COLORS.cyan,
                  padding: "4px 8px",
                  borderRadius: "5px",
                  fontSize: "10px",
                  cursor: "pointer"
                }}
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* LOADING */}
      {loading && (
        <div style={{ color: COLORS.muted, fontSize: "12px" }}>
          Processing query...
        </div>
      )}

      {/* ERROR */}
      {data?.error && (
        <div style={{
          background: "#2a0000",
          border: `1px solid ${COLORS.red}33`,
          padding: "10px",
          borderRadius: "6px",
          color: COLORS.red,
          fontSize: "12px"
        }}>
          {data.error}
        </div>
      )}

      {/* UNKNOWN / MESSAGE */}
      {data && data.success === false && (
        <div style={{
          background: "#1a1a00",
          border: `1px solid ${COLORS.amber}33`,
          padding: "10px",
          borderRadius: "6px",
          color: COLORS.amber,
          fontSize: "12px"
        }}>
          {data.message}
        </div>
      )}

      {/* RESULTS */}
      {data && data.success && !loading && (
        <div style={{
          background: COLORS.card,
          border: `1px solid ${COLORS.border}`,
          borderRadius: "8px",
          padding: "16px"
        }}>

          {/* FILTERS */}
          <div style={{
            fontSize: "10px",
            color: COLORS.muted,
            marginBottom: "8px",
            fontFamily: "monospace"
          }}>
            Filters: {JSON.stringify(data.filters)}
          </div>

          {/* COUNT */}
          <div style={{
            fontSize: "12px",
            marginBottom: "10px"
          }}>
            Results: {data.count}
          </div>

          {/* TABLE */}
          {data.results && data.results.length > 0 ? (
            <table style={{
              width: "100%",
              fontSize: "11px",
              borderCollapse: "collapse"
            }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                  {["Time", "Attack", "Prediction", "Severity", "Src IP", "Dst IP"].map(h => (
                    <th key={h} style={{
                      textAlign: "left",
                      padding: "8px",
                      color: COLORS.muted,
                      fontWeight: 500
                    }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>

              <tbody>
                {data.results.map((row, i) => (
                  <tr key={i} style={{
                    borderBottom: "1px solid #08121f"
                  }}>
                    <td style={{ padding: "8px", color: COLORS.muted }}>
                      {row.time || "—"}
                    </td>

                    <td style={{ padding: "8px", color: COLORS.red }}>
                      {row.attack_type || "—"}
                    </td>

                    <td style={{ padding: "8px" }}>
                      {row.prediction || "—"}
                    </td>

                    <td style={{ padding: "8px", color: COLORS.cyan }}>
                      {row.severity || "—"}
                    </td>

                    <td style={{ padding: "8px" }}>
                      {row.src_ip || "—"}
                    </td>

                    <td style={{ padding: "8px" }}>
                      {row.dst_ip || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div style={{
              color: COLORS.muted,
              fontSize: "12px",
              textAlign: "center",
              padding: "12px"
            }}>
              No results found
            </div>
          )}
        </div>
      )}
    </div>
  );
}