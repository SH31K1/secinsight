import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { ScanSummary } from "../types";
import { useMode } from "../ModeContext";
import ModeToggle from "../components/ModeToggle";
import { Download, FileText } from "lucide-react";
import { ErrorPanel } from "./Dashboard";

export default function Reports() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [generating, setGenerating] = useState<string | null>(null);
  const { mode } = useMode();

  useEffect(() => {
    api
      .listScans()
      .then((list) => {
        setScans(list);
        if (list.length > 0) setSelectedId(list[0].id);
      })
      .catch((e) => setError(e.message));
  }, []);

  async function generate(format: "pdf" | "html" | "markdown") {
    if (!selectedId) return;
    setGenerating(format);
    try {
      const res = await api.generateReport(selectedId, format, mode, true);
      window.open(api.downloadUrl(res.report_id), "_blank");
    } catch (e: any) {
      setError(e.message);
    } finally {
      setGenerating(null);
    }
  }

  if (error) return <div className="p-8"><ErrorPanel message={error} /></div>;

  return (
    <div className="p-8 max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-semibold text-slate-100">Reports</h1>
          <p className="text-slate-500 text-sm mt-1">
            Generate a {mode === "student" ? "beginner-friendly" : "professional"} PDF, HTML, or Markdown report.
          </p>
        </div>
        <ModeToggle />
      </div>

      {scans.length === 0 ? (
        <p className="text-slate-500 text-sm">No scans available yet — analyze one first.</p>
      ) : (
        <div className="bg-ink-800 border border-ink-700 rounded-xl p-5 space-y-4">
          <div>
            <label className="block text-xs uppercase tracking-wide text-slate-500 mb-2">Scan</label>
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="bg-ink-900 border border-ink-600 rounded-md px-3 py-2 text-sm text-slate-200 w-full"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.tool.toUpperCase()} — {s.target || "unknown"} — score {s.score} —{" "}
                  {new Date(s.created_at).toLocaleString()}
                </option>
              ))}
            </select>
          </div>

          <div className="flex gap-3">
            {(["pdf", "html", "markdown"] as const).map((f) => (
              <button
                key={f}
                onClick={() => generate(f)}
                disabled={generating === f}
                className="flex-1 flex items-center justify-center gap-2 bg-signal-500 hover:bg-signal-400 disabled:opacity-50 text-white text-sm font-medium py-2.5 rounded-md transition-colors"
              >
                {generating === f ? (
                  "Generating..."
                ) : (
                  <>
                    <Download size={14} /> {f.toUpperCase()}
                  </>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="bg-ink-800 border border-ink-700 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-2">
          <FileText size={15} className="text-signal-400" />
          <h2 className="font-display font-medium text-slate-200 text-sm">CLI equivalent</h2>
        </div>
        <code className="text-xs text-slate-400 font-mono block">
          secinsight analyze scan.xml {mode === "student" ? "--student" : "--pro"} --pdf --html --markdown
        </code>
      </div>
    </div>
  );
}
