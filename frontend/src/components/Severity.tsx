import type { Severity, SeverityCounts } from "../types";

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#C4374D",
  high: "#DB6B2C",
  medium: "#C9A227",
  low: "#3C7DD9",
  info: "#5B6472",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium uppercase tracking-wide"
      style={{ backgroundColor: `${SEVERITY_COLORS[severity]}22`, color: SEVERITY_COLORS[severity] }}
    >
      <span className="severity-dot" style={{ backgroundColor: SEVERITY_COLORS[severity] }} />
      {severity}
    </span>
  );
}

export function gradeColor(grade: string): string {
  const map: Record<string, string> = {
    A: "#3EAE6B",
    B: "#8AB33E",
    C: "#C9A227",
    D: "#DB6B2C",
    F: "#C4374D",
  };
  return map[grade] || "#5B6472";
}

export function ScoreGauge({ score, grade, size = 96 }: { score: number; grade: string; size?: number }) {
  const color = gradeColor(grade);
  const circumference = 2 * Math.PI * 42;
  const offset = circumference * (1 - score / 100);
  return (
    <div className="relative scan-surface rounded-full" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 100 100" className="rotate-[-90deg]">
        <circle cx="50" cy="50" r="42" fill="none" stroke="#1B2432" strokeWidth="8" />
        <circle
          cx="50"
          cy="50"
          r="42"
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display font-bold text-xl leading-none" style={{ color }}>
          {score}
        </span>
        <span className="text-[10px] text-slate-500 mt-0.5">grade {grade}</span>
      </div>
    </div>
  );
}

export function SeverityCountPills({ counts }: { counts: SeverityCounts }) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return (
    <div className="flex flex-wrap gap-3">
      {order.map((sev) => (
        <div key={sev} className="flex items-center gap-1.5">
          <SeverityBadge severity={sev} />
          <span className="text-xs text-slate-400 font-mono">{counts[sev] ?? 0}</span>
        </div>
      ))}
    </div>
  );
}
