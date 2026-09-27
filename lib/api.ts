const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000";

export type GitHubIdentity = {
  login: string;
  account_id: number;
  scopes: string[];
};

export type GitHubRepository = {
  full_name: string;
  private: boolean;
  default_branch: string;
  html_url: string;
  updated_at: string;
  archived: boolean;
};

export type RepositoryAnalysis = {
  repository: string;
  default_branch: string;
  visibility: string;
  dependency_count: number;
  ecosystems: string[];
  packages: { name: string; version: string | null; purl: string | null }[];
  dependency_status: "available" | "unavailable";
  dependency_source: "github_sbom" | "github_manifests" | "unavailable";
  dependency_message: string | null;
  vulnerability_status: "available" | "unavailable";
  vulnerability_message: string | null;
  risk: {
    composite_score: number;
    risk_level: "critical" | "high" | "medium" | "low";
    computed_at: string;
    dependency_exposures: {
      ecosystem: string;
      package_name: string;
      resolved_version: string | null;
      severity: string;
      advisory_id: string;
      match_reason: string;
    }[];
  };
};

function githubHeaders(token: string): HeadersInit {
  return { "X-GitHub-Token": token };
}

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
  validateToken: (token: string) =>
    request<GitHubIdentity>("/api/v1/github/validate", {
      method: "POST",
      headers: githubHeaders(token),
    }),
  repositories: (token: string) =>
    request<{ items: GitHubRepository[] }>("/api/v1/github/repositories", {
      headers: githubHeaders(token),
    }),
  analyze: (repository: string, token: string) =>
    request<RepositoryAnalysis>(`/api/v1/repositories/${repository}/analyze`, {
      method: "POST",
      headers: githubHeaders(token),
    }),
};
