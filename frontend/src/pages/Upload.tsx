import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { UploadCloud, FileWarning, Loader2 } from "lucide-react";
import { api } from "../api/client";

const TOOLS = ["auto-detect", "nmap", "nikto", "burp", "zap", "nessus", "openvas", "gobuster", "dirsearch"];

export default function Upload() {
  const [dragOver, setDragOver] = useState(false);
  const [tool, setTool] = useState("auto-detect");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  async function handleFile(file: File) {
    setLoading(true);
    setError(null);
    try {
      const scan = await api.uploadScan(file, tool === "auto-detect" ? undefined : tool);
      navigate(`/scans/${scan.id}`);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="p-8 max-w-2xl">
      <h1 className="font-display text-2xl font-semibold text-slate-100">Analyze a scan</h1>
      <p className="text-slate-500 text-sm mt-1 mb-6">
        Upload output from Nmap, Nikto, Burp, ZAP, Nessus, OpenVAS, Gobuster, or Dirsearch.
      </p>

      <div className="mb-4">
        <label className="block text-xs uppercase tracking-wide text-slate-500 mb-2">Tool</label>
        <select
          value={tool}
          onChange={(e) => setTool(e.target.value)}
          className="bg-ink-800 border border-ink-600 rounded-md px-3 py-2 text-sm text-slate-200 w-full"
        >
          {TOOLS.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files[0];
          if (f) handleFile(f);
        }}
        onClick={() => inputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors ${
          dragOver ? "border-signal-400 bg-signal-500/5" : "border-ink-600 hover:border-ink-500"
        }`}
      >
        {loading ? (
          <Loader2 className="mx-auto text-signal-400 animate-spin" size={28} />
        ) : (
          <UploadCloud className="mx-auto text-slate-500" size={28} />
        )}
        <p className="text-sm text-slate-400 mt-3">
          {loading ? "Parsing and scoring..." : "Drop a scan file here, or click to browse"}
        </p>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
          }}
        />
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-2 bg-severity-critical/10 border border-severity-critical/30 rounded-lg p-3">
          <FileWarning className="text-[#C4374D] shrink-0 mt-0.5" size={16} />
          <span className="text-sm text-slate-300">{error}</span>
        </div>
      )}

      <div className="mt-8 text-xs text-slate-600 font-mono">
        Prefer the terminal? <span className="text-slate-400">secinsight analyze nmap.xml --pretty</span>
      </div>
    </div>
  );
}
