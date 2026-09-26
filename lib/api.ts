const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

export type ApiMetric = { label: string; value: number; delta: number; note: string };
export type ApiOverview = {
  metrics: ApiMetric[];
  trend: { timestamp: string; score: number }[];
  signal_distribution: { signal: string; percentage: number }[];
  pipeline: { source: string; last_success_at: string | null; cadence: string; status: string }[];
  generated_at: string;
};
export type ApiFinding = {
  risk_id: string;
  repo_name: string;
  actor_login: string;
  composite_score: number;
  risk_level: "critical" | "high" | "medium" | "low";
  primary_signal: string;
  evidence: string;
  signals_fired: string[];
  latest_activity: string;
  data_sources: string[];
};
export type RepositoryAnalysis = {
  repository: string;
  default_branch: string;
  visibility: string;
  dependency_count: number;
  ecosystems: string[];
  packages: { name: string; version: string | null; purl: string | null }[];
  risk: {
    composite_score: number;
    risk_level: string;
    ai_explanation: string | null;
    dependency_exposures: {
      package_name: string;
      resolved_version: string | null;
      severity: string;
      advisory_id: string;
    }[];
  };
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { ...init, cache: "no-store" });
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    const detail =
      payload && typeof payload === "object" && "detail" in payload
        ? (payload as { detail?: unknown }).detail
        : null;
    throw new Error(typeof detail === "string" ? detail : `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  overview: () => request<ApiOverview>("/api/v1/dashboard/overview"),
  findings: () => request<{ items: ApiFinding[] }>("/api/v1/findings?limit=100"),
  validateToken: (token: string) =>
    request<{ login: string }>("/api/v1/github/validate", {
      method: "POST",
      headers: { "X-GitHub-Token": token },
    }),
  analyze: (repository: string, token?: string) =>
    request<RepositoryAnalysis>(`/api/v1/repositories/${repository}/analyze`, {
      method: "POST",
      headers: token ? { "X-GitHub-Token": token } : undefined,
    }),
};
