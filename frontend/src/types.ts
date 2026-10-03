export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  finding_id: string;
  title: string;
  severity: Severity;
  tool: string;
  description: string;
  host?: string | null;
  port?: number | null;
  protocol?: string | null;
  service?: string | null;
  path?: string | null;
  cve?: string | null;
  cvss?: number | null;
  evidence?: string | null;
  recommendation?: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanSummary {
  id: string;
  tool: string;
  target?: string | null;
  score: number;
  grade: string;
  counts: SeverityCounts;
  created_at: string;
}

export interface Scan extends ScanSummary {
  source_filename?: string | null;
  findings: Finding[];
}

export interface DashboardData {
  total_scans: number;
  average_score: number;
  tools_used: Record<string, number>;
  severity_totals: SeverityCounts;
  recent_scans: ScanSummary[];
  score_trend: { timestamp: string; score: number; tool: string }[];
}

export interface CompareResult {
  old_score: number;
  new_score: number;
  score_delta: number;
  new_findings: Finding[];
  resolved_findings: Finding[];
  unchanged_findings: Finding[];
  summary: string;
}

export type Mode = "student" | "pro";
