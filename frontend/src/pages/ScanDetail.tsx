import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "../api/client";
import type { Scan } from "../types";
import { ScoreGauge, SeverityBadge, SeverityCountPills } from "../components/Severity";
import { useMode } from "../ModeContext";
import ModeToggle from "../components/ModeToggle";
import { Sparkles, Wrench, Route, Download } from "lucide-react";
import { ErrorPanel } from "./Dashboard";

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [aiText, setAiText] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const { mode } = useMode();

  useEffect(() => {
    if (!id) return;
    api.getScan(id, filter || undefined).then(setScan).catch((e) => setError(e.message));
  }, [id, filter]);

  async function runAI(kind: "summary" | "fix" | "story") {
    if (!id) return;
    setAiLoading(kind);
    setAiText(null);
    try {
      const res =
        kind === "summary"
          ? await api.aiSummary(id, mode === "student")
          : kind === "fix"
          ? await api.aiFix(id)
          : await api.story(id);
      setAiText(res.text);
    } catch (e: any) {
      setAiText(`Error: ${e.message}`);
    } finally {
      setAiLoading(null);
    }
  }

  async function download(format: "pdf" | "html" | "markdown") {
    if (!id) return;
    const res = await api.generateReport(id, format, mode, true);
    window.open(api.downloadUrl(res.report_id), "_blank");
  }

  if (error) return <div className="p-8"><ErrorPanel message={error} /></div>;
  if (!scan) return <div className="p-8 text-slate-500">Loading scan...</div>;

  return (
    <div className="p-8 max-w-5xl space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs text-slate-500 mb-1">
            <Link to="/" className="hover:text-slate-300">Dashboard</Link> / Scan detail
          </div>
          <h1 className="font-display text-2xl font-semibold text-slate-100">
            {scan.tool.toUpperCase()} scan
          </h1>
          <p className="text-slate-500 text-sm mt-1">{scan.target || "Unknown target"}</p>
        </div>
        <ModeToggle />
      </div>

      <div className="bg-ink-800 border border-ink-700 rounded-xl p-5 flex items-center gap-6">
        <ScoreGauge score={scan.score} grade={scan.grade} size={100} />
        <div className="flex-1">
          <SeverityCountPills counts={scan.counts} />
          <div className="flex gap-2 mt-4">
            <ActionButton onClick={() => runAI("summary")} loading={aiLoading === "summary"} icon={Sparkles} label="AI Summary" />
            <ActionButton onClick={() => runAI("fix")} loading={aiLoading === "fix"} icon={Wrench} label="AI Fix Plan" />
            <ActionButton onClick={() => runAI("story")} loading={aiLoading === "story"} icon={Route} label="Attack Story" />
          </div>
        </div>
      </div>

      {aiText && (
        <div className="bg-ink-800 border border-signal-500/30 rounded-xl p-5">
          <p className="text-sm text-slate-300 whitespace-pre-line leading-relaxed">{aiText}</p>
        </div>
      )}

      <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-display font-medium text-slate-200 text-sm">Export report</h2>
        </div>
        <div className="flex gap-2">
          {(["pdf", "html", "markdown"] as const).map((f) => (
            <button
              key={f}
              onClick={() => download(f)}
              className="flex items-center gap-1.5 text-xs font-medium bg-ink-700 hover:bg-ink-600 text-slate-200 px-3 py-1.5 rounded-md transition-colors"
            >
              <Download size={13} /> {f.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-display font-medium text-slate-200 text-sm">
            Findings ({scan.findings.length})
          </h2>
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="filter e.g. severity>=high"
            className="bg-ink-900 border border-ink-600 rounded-md px-3 py-1.5 text-xs font-mono text-slate-300 w-64"
          />
        </div>
        <div className="divide-y divide-ink-700">
          {scan.findings.map((f) => (
            <div key={f.finding_id} className="py-3">
              <div className="flex items-center gap-2 mb-1">
                <SeverityBadge severity={f.severity} />
                <span className="text-sm font-medium text-slate-200">{f.title}</span>
              </div>
              <div className="text-xs text-slate-500 font-mono mb-1">
                {f.host}
                {f.port ? `:${f.port}` : ""} {f.path ? `${f.path}` : ""} {f.cve ? `· ${f.cve}` : ""}
              </div>
              {f.description && <p className="text-sm text-slate-400">{f.description}</p>}
              {f.recommendation && (
                <p className="text-xs text-emerald-400/90 mt-1">Fix: {f.recommendation}</p>
              )}
            </div>
          ))}
          {scan.findings.length === 0 && (
            <p className="text-sm text-slate-500 py-4">No findings match this filter.</p>
          )}
        </div>
      </div>
    </div>
  );
}

function ActionButton({
  onClick,
  loading,
  icon: Icon,
  label,
}: {
  onClick: () => void;
  loading: boolean;
  icon: any;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      disabled={loading}
      className="flex items-center gap-1.5 text-xs font-medium bg-signal-500/15 hover:bg-signal-500/25 text-signal-400 border border-signal-500/30 px-3 py-1.5 rounded-md transition-colors disabled:opacity-50"
    >
      <Icon size={13} /> {loading ? "Working..." : label}
    </button>
  );
}
