import React, { useState, useEffect, useCallback } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS = {
  critical: "#ff1744", high: "#ff6d00", medium: "#ffd600",
  low: "#00e676", info: "#448aff",
};
const STATUS_COLORS = {
  open: "#ff1744", investigating: "#ff9100", mitigated: "#ffd600",
  resolved: "#00e676", closed: "#90a4ae",
};

function useIncidents() {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/incidents`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setIncidents(await res.json());
      setError(null);
    } catch (e) {
      setError(e.message);
      setIncidents(getMockData());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  return { incidents, loading, error, refetch: fetchIncidents };
}

function getMockData() {
  return [
    { id: "INC-001", title: "Database connection pool exhausted", severity: "critical", status: "open", created_at: "2025-01-15T08:30:00Z", service: "auth-service", alert_count: 12, assignee: null, description: "Connection pool on primary DB reached max capacity. Multiple services affected." },
    { id: "INC-002", title: "High error rate on payment API", severity: "high", status: "investigating", created_at: "2025-01-15T09:15:00Z", service: "payment-service", alert_count: 8, assignee: "oncall-1", description: "5xx error rate exceeded 10% threshold for payment processing endpoint." },
    { id: "INC-003", title: "Disk usage above 85% on worker-03", severity: "medium", status: "investigating", created_at: "2025-01-15T10:00:00Z", service: "worker-03", alert_count: 3, assignee: "ops-team", description: "Root partition disk usage at 87%. Projected to reach 90% in 4 hours." },
    { id: "INC-004", title: "SSL certificate expiry in 7 days", severity: "low", status: "open", created_at: "2025-01-15T07:00:00Z", service: "cdn-edge", alert_count: 1, assignee: null, description: "TLS certificate for cdn.example.com expires on Jan 22." },
    { id: "INC-005", title: "Deploy canary metrics nominal", severity: "info", status: "closed", created_at: "2025-01-14T22:00:00Z", service: "frontend", alert_count: 1, assignee: "ci-bot", description: "Canary deployment passed all health checks. Promoted to stable." },
    { id: "INC-006", title: "Memory leak in order processor", severity: "high", status: "mitigated", created_at: "2025-01-15T06:45:00Z", service: "order-service", alert_count: 5, assignee: "platform-team", description: "RSS growth of ~50MB/hr detected. Workaround: periodic restarts scheduled." },
  ];
}

function Badge({ label, color }) {
  return (
    <span style={{
      display: "inline-block", padding: "2px 10px", borderRadius: 12,
      fontSize: 12, fontWeight: 600, color: "#fff", backgroundColor: color,
      textTransform: "uppercase", letterSpacing: 0.5,
    }}>{label}</span>
  );
}

function FilterBar({ activeSeverities, onToggle, onClear, activeStatuses, onToggleStatus, onClearStatus }) {
  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 16 }}>
      <span style={{ fontWeight: 600, fontSize: 13, marginRight: 4 }}>Severity:</span>
      {Object.keys(SEVERITY_COLORS).map((s) => (
        <button key={s} onClick={() => onToggle(s)} style={{
          padding: "4px 12px", borderRadius: 6, border: "1px solid", cursor: "pointer",
          fontSize: 12, fontWeight: 600, textTransform: "uppercase",
          backgroundColor: activeSeverities.has(s) ? SEVERITY_COLORS[s] : "transparent",
          color: activeSeverities.has(s) ? "#fff" : SEVERITY_COLORS[s],
          borderColor: SEVERITY_COLORS[s],
        }}>{s}</button>
      ))}
      <button onClick={onClear} style={{ marginLeft: 4, fontSize: 11, cursor: "pointer", border: "none", background: "none", color: "#888" }}>Clear</button>
      <span style={{ fontWeight: 600, fontSize: 13, marginLeft: 16, marginRight: 4 }}>Status:</span>
      {Object.keys(STATUS_COLORS).map((s) => (
        <button key={s} onClick={() => onToggleStatus(s)} style={{
          padding: "4px 12px", borderRadius: 6, border: "1px solid", cursor: "pointer",
          fontSize: 12, fontWeight: 600, textTransform: "uppercase",
          backgroundColor: activeStatuses.has(s) ? STATUS_COLORS[s] : "transparent",
          color: activeStatuses.has(s) ? "#fff" : STATUS_COLORS[s],
          borderColor: STATUS_COLORS[s],
        }}>{s}</button>
      ))}
      <button onClick={onClearStatus} style={{ marginLeft: 4, fontSize: 11, cursor: "pointer", border: "none", background: "none", color: "#888" }}>Clear</button>
    </div>
  );
}

function IncidentTable({ incidents, onSelect }) {
  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
      <thead>
        <tr style={{ borderBottom: "2px solid #333", textAlign: "left" }}>
          <th style={{ padding: "8px 12px" }}>ID</th>
          <th style={{ padding: "8px 12px" }}>Title</th>
          <th style={{ padding: "8px 12px" }}>Severity</th>
          <th style={{ padding: "8px 12px" }}>Status</th>
          <th style={{ padding: "8px 12px" }}>Service</th>
          <th style={{ padding: "8px 12px" }}>Alerts</th>
          <th style={{ padding: "8px 12px" }}>Created</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((inc) => (
          <tr key={inc.id} onClick={() => onSelect(inc)} style={{
            borderBottom: "1px solid #222", cursor: "pointer",
            backgroundColor: "transparent",
            borderLeft: `4px solid ${SEVERITY_COLORS[inc.severity] || "#555"}`,
          }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "#1a1a2e"}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}
          >
            <td style={{ padding: "8px 12px", fontFamily: "monospace" }}>{inc.id}</td>
            <td style={{ padding: "8px 12px", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</td>
            <td style={{ padding: "8px 12px" }}><Badge label={inc.severity} color={SEVERITY_COLORS[inc.severity]} /></td>
            <td style={{ padding: "8px 12px" }}><Badge label={inc.status} color={STATUS_COLORS[inc.status]} /></td>
            <td style={{ padding: "8px 12px", fontFamily: "monospace", fontSize: 13 }}>{inc.service}</td>
            <td style={{ padding: "8px 12px", textAlign: "center" }}>{inc.alert_count}</td>
            <td style={{ padding: "8px 12px", fontSize: 12, color: "#aaa" }}>{new Date(inc.created_at).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DetailPanel({ incident, onClose, onAcknowledge }) {
  if (!incident) return null;
  return (
    <div style={{
      position: "fixed", right: 0, top: 0, bottom: 0, width: 420,
      backgroundColor: "#12122a", borderLeft: "1px solid #333",
      padding: 24, overflowY: "auto", zIndex: 50, boxShadow: "-4px 0 24px rgba(0,0,0,0.5)",
    }}>
      <button onClick={onClose} style={{ position: "absolute", top: 12, right: 16, background: "none", border: "none", color: "#aaa", fontSize: 20, cursor: "pointer" }}>✕</button>
      <h2 style={{ marginTop: 0, fontSize: 18 }}>{incident.id}</h2>
      <h3 style={{ fontSize: 15, marginTop: 4, marginBottom: 16, color: "#ccc" }}>{incident.title}</h3>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <Badge label={incident.severity} color={SEVERITY_COLORS[incident.severity]} />
        <Badge label={incident.status} color={STATUS_COLORS[incident.status]} />
      </div>
      <div style={{ fontSize: 13, lineHeight: 1.7 }}>
        <p><strong>Service:</strong> <code>{incident.service}</code></p>
        <p><strong>Alert Count:</strong> {incident.alert_count}</p>
        <p><strong>Assignee:</strong> {incident.assignee || "Unassigned"}</p>
        <p><strong>Created:</strong> {new Date(incident.created_at).toLocaleString()}</p>
        <p style={{ marginTop: 12 }}><strong>Description:</strong></p>
        <p style={{ color: "#bbb", marginTop: 4 }}>{incident.description}</p>
      </div>
      {incident.status === "open" && (
        <button onClick={() => onAcknowledge(incident.id)} style={{
          marginTop: 20, width: "100%", padding: "10px 0", borderRadius: 6,
          backgroundColor: "#ff9100", color: "#fff", fontWeight: 600,
          border: "none", cursor: "pointer", fontSize: 14,
        }}>Acknowledge</button>
      )}
    </div>
  );
}

export default function App() {
  const { incidents, loading, refetch } = useIncidents();
  const [selected, setSelected] = useState(null);
  const [sevFilters, setSevFilters] = useState(new Set());
  const [statusFilters, setStatusFilters] = useState(new Set());

  const toggleSev = (s) => {
    const next = new Set(sevFilters);
    next.has(s) ? next.delete(s) : next.add(s);
    setSevFilters(next);
  };
  const toggleStatus = (s) => {
    const next = new Set(statusFilters);
    next.has(s) ? next.delete(s) : next.add(s);
    setStatusFilters(next);
  };

  const filtered = incidents
    .filter((i) => sevFilters.size === 0 || sevFilters.has(i.severity))
    .filter((i) => statusFilters.size === 0 || statusFilters.has(i.status))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  const acknowledge = async (id) => {
    try {
      await fetch(`${API_BASE}/incidents/${id}/acknowledge`, { method: "POST" });
    } catch { /* mock mode */ }
    refetch();
    setSelected(null);
  };

  return (
    <div style={{ fontFamily: "'Inter', system-ui, sans-serif", backgroundColor: "#0d0d1a", color: "#eee", minHeight: "100vh", padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <h1 style={{ margin: 0, fontSize: 22 }}>🔔 Incident Triage Dashboard</h1>
        <button onClick={refetch} style={{ padding: "6px 16px", borderRadius: 6, border: "1px solid #444", background: "#1a1a2e", color: "#ccc", cursor: "pointer", fontSize: 13 }}>Refresh</button>
      </div>
      <FilterBar
        activeSeverities={sevFilters} onToggle={toggleSev} onClear={() => setSevFilters(new Set())}
        activeStatuses={statusFilters} onToggleStatus={toggleStatus} onClearStatus={() => setStatusFilters(new Set())}
      />
      {loading ? <p style={{ color: "#888" }}>Loading incidents…</p> : (
        <>
          <p style={{ fontSize: 12, color: "#666", marginBottom: 8 }}>Showing {filtered.length} of {incidents.length} incidents</p>
          <IncidentTable incidents={filtered} onSelect={setSelected} />
        </>
      )}
      {selected && <DetailPanel incident={selected} onClose={() => setSelected(null)} onAcknowledge={acknowledge} />}
    </div>
  );
}