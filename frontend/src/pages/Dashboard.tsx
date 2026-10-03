import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";
import { api } from "../api/client";
import type { DashboardData } from "../types";
import { gradeColor, SeverityCountPills } from "../components/Severity";
import { useMode } from "../ModeContext";
import { AlertTriangle, ScanLine } from "lucide-react";

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { mode } = useMode();

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) {
    return (
      <div className="p-8">
        <ErrorPanel message={error} />
      </div>
    );
  }
  if (!data) return <div className="p-8 text-slate-500">Loading dashboard...</div>;

  const grade = scoreToGrade(data.average_score);

  return (
    <div className="p-8 space-y-6 max-w-6xl">
      <div>
        <h1 className="font-display text-2xl font-semibold text-slate-100">Dashboard</h1>
        <p className="text-slate-500 text-sm mt-1">
          {mode === "student"
            ? "A quick look at how secure your scanned targets are overall."
            : "Aggregate security posture across all imported scans."}
        </p>
      </div>

      {data.total_scans === 0 ? (
        <EmptyState />
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard label="Total scans" value={data.total_scans.toString()} />
            <StatCard
              label="Average score"
              value={`${data.average_score}/100`}
              accent={gradeColor(grade)}
            />
            <StatCard label="Tools used" value={Object.keys(data.tools_used).length.toString()} />
          </div>

          <div className="bg-ink-800 border border-ink-700 rounded-xl p-5 scan-surface">
            <div className="flex items-center gap-2 mb-4">
              <ScanLine size={16} className="text-signal-400" />
              <h2 className="font-display font-medium text-slate-200 text-sm">Score trend</h2>
            </div>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={data.score_trend}>
                <CartesianGrid stroke="#1B2432" vertical={false} />
                <XAxis
                  dataKey="timestamp"
                  tick={{ fontSize: 10, fill: "#5B6472" }}
                  tickFormatter={(v) => new Date(v).toLocaleDateString()}
                  axisLine={{ stroke: "#283444" }}
                />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#5B6472" }} axisLine={{ stroke: "#283444" }} />
                <Tooltip
                  contentStyle={{ background: "#131A24", border: "1px solid #283444", fontSize: 12 }}
                  labelFormatter={(v) => new Date(v).toLocaleString()}
                />
                <Line type="monotone" dataKey="score" stroke="#8A80EC" strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
            <h2 className="font-display font-medium text-slate-200 text-sm mb-3">Findings by severity (all scans)</h2>
            <SeverityCountPills counts={data.severity_totals} />
          </div>

          <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
            <h2 className="font-display font-medium text-slate-200 text-sm mb-3">Recent scans</h2>
            <div className="divide-y divide-ink-700">
              {data.recent_scans.map((s) => (
                <Link
                  key={s.id}
                  to={`/scans/${s.id}`}
                  className="flex items-center justify-between py-3 hover:bg-ink-700/40 -mx-2 px-2 rounded transition-colors"
                >
                  <div>
                    <div className="text-sm font-medium text-slate-200 font-mono">{s.tool.toUpperCase()}</div>
                    <div className="text-xs text-slate-500">{s.target || "unknown target"}</div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-slate-500">{new Date(s.created_at).toLocaleString()}</span>
                    <span
                      className="font-display font-semibold text-sm px-2 py-1 rounded"
                      style={{ color: gradeColor(s.grade), backgroundColor: `${gradeColor(s.grade)}18` }}
                    >
                      {s.score}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function scoreToGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function StatCard({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
      <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">{label}</div>
      <div className="font-display text-2xl font-semibold" style={{ color: accent || "#E2E8F0" }}>
        {value}
      </div>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="bg-ink-800 border border-dashed border-ink-600 rounded-xl p-10 text-center">
      <ScanLine className="mx-auto text-slate-600 mb-3" size={28} />
      <h3 className="font-display text-slate-200 font-medium">No scans yet</h3>
      <p className="text-slate-500 text-sm mt-1 mb-4">
        Analyze your first scan to populate the dashboard.
      </p>
      <Link
        to="/upload"
        className="inline-block bg-signal-500 hover:bg-signal-400 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
      >
        Analyze a scan
      </Link>
    </div>
  );
}

export function ErrorPanel({ message }: { message: string }) {
  return (
    <div className="bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-4 flex items-start gap-3">
      <AlertTriangle className="text-[#C4374D] shrink-0 mt-0.5" size={18} />
      <div>
        <div className="text-sm font-medium text-slate-200">Couldn't reach the API</div>
        <div className="text-xs text-slate-500 mt-1">{message}</div>
      </div>
    </div>
  );
}
