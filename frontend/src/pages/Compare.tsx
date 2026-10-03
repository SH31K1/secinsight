import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { CompareResult, ScanSummary } from "../types";
import { SeverityBadge, gradeColor } from "../components/Severity";
import { ArrowRight, TrendingUp, TrendingDown } from "lucide-react";
import { ErrorPanel } from "./Dashboard";

export default function Compare() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api
      .listScans()
      .then((list) => {
        setScans(list);
        if (list.length >= 2) {
          setNewId(list[0].id);
          setOldId(list[1].id);
        } else if (list.length === 1) {
          setNewId(list[0].id);
        }
      })
      .catch((e) => setError(e.message));
  }, []);

  async function runCompare() {
    if (!oldId || !newId) return;
    setLoading(true);
    setError(null);
    try {
      const r = await api.compare(oldId, newId);
      setResult(r);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 max-w-4xl space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold text-slate-100">Compare scans</h1>
        <p className="text-slate-500 text-sm mt-1">
          See what's new, fixed, or unchanged between two scans of the same target over time.
        </p>
      </div>

      {error && <ErrorPanel message={error} />}

      {scans.length < 2 ? (
        <p className="text-slate-500 text-sm">You need at least two analyzed scans to compare.</p>
      ) : (
        <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <label className="block text-xs uppercase tracking-wide text-slate-500 mb-2">Old scan</label>
              <ScanSelect scans={scans} value={oldId} onChange={setOldId} />
            </div>
            <ArrowRight className="text-slate-600 mb-2.5" size={18} />
            <div className="flex-1">
              <label className="block text-xs uppercase tracking-wide text-slate-500 mb-2">New scan</label>
              <ScanSelect scans={scans} value={newId} onChange={setNewId} />
            </div>
            <button
              onClick={runCompare}
              disabled={loading}
              className="bg-signal-500 hover:bg-signal-400 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
            >
              {loading ? "Comparing..." : "Compare"}
            </button>
          </div>
        </div>
      )}

      {result && (
        <>
          <div className="bg-ink-800 border border-ink-700 rounded-xl p-5 flex items-center gap-4">
            <div className="flex items-center gap-3">
              <span className="font-display text-2xl font-semibold" style={{ color: gradeColor(scoreGrade(result.old_score)) }}>
                {result.old_score}
              </span>
              <ArrowRight size={16} className="text-slate-600" />
              <span className="font-display text-2xl font-semibold" style={{ color: gradeColor(scoreGrade(result.new_score)) }}>
                {result.new_score}
              </span>
            </div>
            <div
              className={`flex items-center gap-1 text-sm font-medium ${
                result.score_delta >= 0 ? "text-emerald-400" : "text-rose-400"
              }`}
            >
              {result.score_delta >= 0 ? <TrendingUp size={15} /> : <TrendingDown size={15} />}
              {result.score_delta >= 0 ? "+" : ""}
              {result.score_delta}
            </div>
            <p className="text-sm text-slate-400 flex-1">{result.summary}</p>
          </div>

          <FindingList title={`New findings (${result.new_findings.length})`} findings={result.new_findings} tone="new" />
          <FindingList title={`Resolved findings (${result.resolved_findings.length})`} findings={result.resolved_findings} tone="resolved" />
        </>
      )}
    </div>
  );
}

function scoreGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function ScanSelect({
  scans,
  value,
  onChange,
}: {
  scans: ScanSummary[];
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="bg-ink-900 border border-ink-600 rounded-md px-3 py-2 text-sm text-slate-200 w-full"
    >
      {scans.map((s) => (
        <option key={s.id} value={s.id}>
          {s.tool.toUpperCase()} — {new Date(s.created_at).toLocaleString()} — score {s.score}
        </option>
      ))}
    </select>
  );
}

function FindingList({ title, findings, tone }: { title: string; findings: any[]; tone: "new" | "resolved" }) {
  if (findings.length === 0) return null;
  return (
    <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
      <h2 className="font-display font-medium text-slate-200 text-sm mb-3">{title}</h2>
      <div className="divide-y divide-ink-700">
        {findings.map((f) => (
          <div key={f.finding_id} className={`flex items-center gap-3 py-2 ${tone === "resolved" ? "opacity-60" : ""}`}>
            <SeverityBadge severity={f.severity} />
            <span className="text-sm text-slate-300">{f.title}</span>
            <span className="text-xs text-slate-500 font-mono ml-auto">{f.host}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
