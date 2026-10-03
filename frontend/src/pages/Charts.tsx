import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Cell, PieChart, Pie, Legend } from "recharts";
import { api } from "../api/client";
import type { Scan, ScanSummary } from "../types";
import { SEVERITY_COLORS } from "../components/Severity";
import { ErrorPanel } from "./Dashboard";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export default function Charts() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listScans()
      .then((list) => {
        setScans(list);
        if (list.length > 0) setSelectedId(list[0].id);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    api.getScan(selectedId).then(setScan).catch((e) => setError(e.message));
  }, [selectedId]);

  if (error) return <div className="p-8"><ErrorPanel message={error} /></div>;

  if (scans.length === 0) {
    return (
      <div className="p-8">
        <h1 className="font-display text-2xl font-semibold text-slate-100 mb-2">Charts</h1>
        <p className="text-slate-500 text-sm">Analyze a scan first to see charts here.</p>
      </div>
    );
  }

  const severityData = scan
    ? SEVERITIES.map((s) => ({ name: s, count: scan.counts[s] ?? 0 }))
    : [];

  const hostMap: Record<string, number> = {};
  scan?.findings.forEach((f) => {
    const h = f.host || "unknown";
    hostMap[h] = (hostMap[h] || 0) + 1;
  });
  const hostData = Object.entries(hostMap).map(([host, count]) => ({ name: host, value: count }));

  return (
    <div className="p-8 max-w-5xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100">Charts</h1>
          <p className="text-slate-500 text-sm mt-1">Visualize findings for a specific scan.</p>
        </div>
        <select
          value={selectedId}
          onChange={(e) => setSelectedId(e.target.value)}
          className="bg-ink-800 border border-ink-600 rounded-md px-3 py-2 text-sm text-slate-200"
        >
          {scans.map((s) => (
            <option key={s.id} value={s.id}>
              {s.tool.toUpperCase()} — {s.target || "unknown"} ({new Date(s.created_at).toLocaleDateString()})
            </option>
          ))}
        </select>
      </div>

      {scan && (
        <>
          <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
            <h2 className="font-display font-medium text-slate-200 text-sm mb-4">Findings by severity</h2>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={severityData}>
                <CartesianGrid stroke="#1B2432" vertical={false} />
                <XAxis dataKey="name" tick={{ fontSize: 11, fill: "#5B6472" }} axisLine={{ stroke: "#283444" }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#5B6472" }} axisLine={{ stroke: "#283444" }} />
                <Tooltip contentStyle={{ background: "#131A24", border: "1px solid #283444", fontSize: 12 }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name as keyof typeof SEVERITY_COLORS]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {hostData.length > 1 && (
            <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
              <h2 className="font-display font-medium text-slate-200 text-sm mb-4">Findings by host</h2>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={hostData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    label={(entry) => entry.name}
                  >
                    {hostData.map((_, i) => (
                      <Cell key={i} fill={["#6E62E5", "#3C7DD9", "#C9A227", "#DB6B2C", "#C4374D"][i % 5]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ background: "#131A24", border: "1px solid #283444", fontSize: 12 }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}
    </div>
  );
}
