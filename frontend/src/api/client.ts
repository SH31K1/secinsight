import type { CompareResult, DashboardData, Scan, ScanSummary } from "../types";

const BASE = "/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    const detail = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(detail.detail || `Request failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listTools: () => req<{ tools: string[] }>("/scans/tools"),

  uploadScan: async (file: File, tool?: string): Promise<Scan> => {
    const form = new FormData();
    form.append("file", file);
    const qs = tool ? `?tool=${encodeURIComponent(tool)}` : "";
    return req<Scan>(`/scans${qs}`, { method: "POST", body: form });
  },

  listScans: (tool?: string) => {
    const qs = tool ? `?tool=${encodeURIComponent(tool)}` : "";
    return req<ScanSummary[]>(`/scans${qs}`);
  },

  getScan: (id: string, filter?: string) => {
    const qs = filter ? `?filter=${encodeURIComponent(filter)}` : "";
    return req<Scan>(`/scans/${id}${qs}`);
  },

  deleteScan: (id: string) => req<{ deleted: string }>(`/scans/${id}`, { method: "DELETE" }),

  getRisk: (id: string) => req<any>(`/scans/${id}/risk`),

  explain: (id: string, student: boolean) =>
    req<{ explanations: string[] }>(`/scans/${id}/explain?student=${student}`),

  aiSummary: (id: string, student: boolean) =>
    req<{ text: string }>(`/scans/${id}/ai-summary?student=${student}`),

  aiFix: (id: string) => req<{ text: string }>(`/scans/${id}/ai-fix`),

  story: (id: string) => req<{ text: string }>(`/scans/${id}/story`),

  dashboard: () => req<DashboardData>("/scans/dashboard/overview"),

  compare: (oldId: string, newId: string) => req<CompareResult>(`/compare/${oldId}/${newId}`),

  generateReport: (id: string, format: "pdf" | "html" | "markdown", mode: "pro" | "student", aiSummary: boolean) =>
    req<{ report_id: string; download_url: string }>(
      `/reports/${id}/generate?format=${format}&mode=${mode}&ai_summary=${aiSummary}`,
      { method: "POST" }
    ),

  listReports: (scanId?: string) => {
    const qs = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
    return req<any[]>(`/reports${qs}`);
  },

  downloadUrl: (reportId: string) => `${BASE}/reports/${reportId}/download`,
};
