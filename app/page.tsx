"use client";

import { FormEvent, useMemo, useState } from "react";
import {
  AlertTriangle,
  Boxes,
  CheckCircle2,
  ExternalLink,
  GitBranch,
  KeyRound,
  LockKeyhole,
  LogOut,
  PackageSearch,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api, GitHubRepository, RepositoryAnalysis } from "@/lib/api";

const riskStyles = {
  critical: "border-red-400/25 bg-red-400/10 text-red-300",
  high: "border-amber-300/25 bg-amber-300/10 text-amber-200",
  medium: "border-blue-300/25 bg-blue-300/10 text-blue-200",
  low: "border-emerald-300/25 bg-emerald-300/10 text-emerald-200",
};

export default function Home() {
  const [token, setToken] = useState("");
  const [identity, setIdentity] = useState("");
  const [repositories, setRepositories] = useState<GitHubRepository[]>([]);
  const [selectedRepo, setSelectedRepo] = useState("");
  const [analysis, setAnalysis] = useState<RepositoryAnalysis | null>(null);
  const [query, setQuery] = useState("");
  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  const connected = Boolean(identity);
  const filteredRepositories = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return repositories.filter(
      (repository) => !normalized || repository.full_name.toLowerCase().includes(normalized),
    );
  }, [query, repositories]);

  async function scan(repository: string, credential = token.trim()) {
    if (!repository || !credential) return;
    setScanning(true);
    setError("");
    setAnalysis(null);
    try {
      setAnalysis(await api.analyze(repository, credential));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Repository scan failed");
    } finally {
      setScanning(false);
    }
  }

  async function connect(event: FormEvent) {
    event.preventDefault();
    const credential = token.trim();
    if (!credential) return;
    setConnecting(true);
    setError("");
    try {
      const [user, page] = await Promise.all([
        api.validateToken(credential),
        api.repositories(credential),
      ]);
      const available = page.items.filter((repository) => !repository.archived);
      setIdentity(user.login);
      setRepositories(available);
      const firstRepository = available[0]?.full_name ?? "";
      setSelectedRepo(firstRepository);
      if (firstRepository) await scan(firstRepository, credential);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "GitHub connection failed");
    } finally {
      setConnecting(false);
    }
  }

  function disconnect() {
    setToken("");
    setIdentity("");
    setRepositories([]);
    setSelectedRepo("");
    setAnalysis(null);
    setQuery("");
    setError("");
  }

  if (!connected) {
    return (
      <main className="grid min-h-screen place-items-center px-4 py-10 text-foreground">
        <section className="w-full max-w-2xl rounded-2xl border border-white/[0.08] bg-card/90 p-6 shadow-2xl sm:p-9">
          <div className="mb-7 flex items-center gap-3">
            <div className="grid h-11 w-11 place-items-center rounded-xl border border-emerald-300/20 bg-emerald-300/10 text-emerald-200">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">Connect Sentinel OSS to GitHub</h1>
              <p className="mt-1 text-sm text-muted-foreground">Real repository and dependency data only—no mock findings.</p>
            </div>
          </div>

          <div className="grid gap-3 sm:grid-cols-3">
            {[
              [GitBranch, "Your repositories", "Load repositories your account can access."],
              [Boxes, "Dependency graph", "Read the repository SBOM directly from GitHub."],
              [ShieldAlert, "Real alerts", "Show open GitHub Dependabot vulnerabilities."],
            ].map(([Icon, title, description]) => {
              const FeatureIcon = Icon as typeof GitBranch;
              return (
                <div key={String(title)} className="rounded-xl border border-white/[0.07] bg-black/10 p-4">
                  <FeatureIcon className="h-5 w-5 text-emerald-200" />
                  <p className="mt-3 text-sm font-medium">{String(title)}</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{String(description)}</p>
                </div>
              );
            })}
          </div>

          <form onSubmit={connect} className="mt-7 space-y-4">
            <div className="space-y-2">
              <label htmlFor="github-token" className="text-sm font-medium">Fine-grained GitHub token</label>
              <div className="relative">
                <KeyRound className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input id="github-token" type="password" autoComplete="off" value={token} onChange={(event) => setToken(event.target.value)} className="h-11 pl-9" placeholder="github_pat_••••••••" />
              </div>
            </div>

            <div className="rounded-xl border border-emerald-300/15 bg-emerald-300/[0.05] p-4 text-sm leading-6 text-emerald-50/80">
              <div className="mb-2 flex items-center gap-2 font-medium text-emerald-100"><LockKeyhole className="h-4 w-4" />Required read-only permissions</div>
              <ul className="list-inside list-disc text-xs text-emerald-100/70">
                <li>Metadata: read</li>
                <li>Contents: read</li>
                <li>Dependabot alerts: read</li>
              </ul>
              <p className="mt-2 text-xs">The token is held only in this browser tab&apos;s memory and sent to the local API per request. It is not saved or logged.</p>
            </div>

            {error && <div role="alert" className="rounded-lg border border-red-300/20 bg-red-300/[0.07] px-4 py-3 text-sm text-red-100">{error}</div>}

            <div className="flex flex-col gap-2 sm:flex-row">
              <Button type="submit" className="h-10 flex-1" disabled={!token.trim() || connecting}>
                {connecting ? <RefreshCw className="h-4 w-4 animate-spin" /> : <GitBranch className="h-4 w-4" />}
                {connecting ? "Connecting…" : "Connect GitHub"}
              </Button>
              <Button asChild type="button" variant="secondary" className="h-10">
                <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noreferrer">Create token <ExternalLink className="h-4 w-4" /></a>
              </Button>
            </div>
          </form>
        </section>
      </main>
    );
  }

  const exposures = analysis?.risk.dependency_exposures ?? [];
  const criticalCount = exposures.filter((item) => item.severity === "critical").length;
  const highCount = exposures.filter((item) => item.severity === "high").length;

  return (
    <main className="min-h-screen text-foreground">
      <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#07100f]/90 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-[1500px] items-center gap-3 px-4 sm:px-6">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-emerald-300/10 text-emerald-200"><ShieldCheck className="h-4 w-4" /></div>
          <div><p className="text-sm font-semibold">Sentinel OSS</p><p className="text-[11px] text-muted-foreground">GitHub dependency monitor</p></div>
          <div className="ml-auto flex items-center gap-2">
            <Badge variant="secondary"><CheckCircle2 className="h-3 w-3" />{identity}</Badge>
            <Button size="sm" variant="ghost" onClick={disconnect}><LogOut className="h-4 w-4" />Disconnect</Button>
          </div>
        </div>
      </header>

      <div className="mx-auto grid max-w-[1500px] gap-4 px-4 py-5 sm:px-6 lg:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="h-fit rounded-xl border border-white/[0.07] bg-card/80 p-4 lg:sticky lg:top-20">
          <div className="flex items-center justify-between"><div><h2 className="text-sm font-medium">Repositories</h2><p className="mt-1 text-xs text-muted-foreground">{repositories.length} accessible</p></div><GitBranch className="h-5 w-5 text-muted-foreground" /></div>
          <div className="relative mt-4"><Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input value={query} onChange={(event) => setQuery(event.target.value)} className="pl-9" placeholder="Filter repositories" /></div>
          <div className="mt-3 max-h-[65vh] space-y-1 overflow-y-auto pr-1">
            {filteredRepositories.map((repository) => (
              <button key={repository.full_name} type="button" onClick={() => { setSelectedRepo(repository.full_name); setAnalysis(null); setError(""); }} className={`w-full rounded-lg border px-3 py-2.5 text-left transition ${selectedRepo === repository.full_name ? "border-emerald-300/25 bg-emerald-300/[0.08]" : "border-transparent hover:bg-white/[0.04]"}`}>
                <div className="flex items-center gap-2"><span className="min-w-0 flex-1 truncate text-sm font-medium">{repository.full_name}</span>{repository.private && <LockKeyhole className="h-3.5 w-3.5 text-muted-foreground" />}</div>
                <p className="mt-1 text-[11px] text-muted-foreground">Updated {new Date(repository.updated_at).toLocaleDateString()}</p>
              </button>
            ))}
            {filteredRepositories.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No repositories found.</p>}
          </div>
        </aside>

        <section className="min-w-0 space-y-4">
          <div className="flex flex-col gap-3 rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div><p className="text-xs uppercase tracking-[0.14em] text-emerald-200/70">Selected repository</p><h1 className="mt-1 text-xl font-semibold">{selectedRepo || "Choose a repository"}</h1></div>
            <Button onClick={() => scan(selectedRepo)} disabled={!selectedRepo || scanning}>{scanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <PackageSearch className="h-4 w-4" />}{scanning ? "Scanning GitHub…" : "Scan dependencies"}</Button>
          </div>

          {error && <div role="alert" className="rounded-xl border border-red-300/20 bg-red-300/[0.07] px-4 py-3 text-sm text-red-100">{error}</div>}

          {!analysis && !scanning && <div className="grid min-h-72 place-items-center rounded-xl border border-dashed border-white/10 bg-card/40 p-8 text-center"><div><PackageSearch className="mx-auto h-9 w-9 text-muted-foreground" /><p className="mt-3 font-medium">Ready to inspect GitHub</p><p className="mt-1 text-sm text-muted-foreground">Run a scan to load the current SBOM and open Dependabot alerts.</p></div></div>}

          {analysis && (
            <>
              {analysis.dependency_message && <div className={`flex gap-3 rounded-xl border p-4 text-sm ${analysis.dependency_status === "available" ? "border-blue-300/20 bg-blue-300/[0.07] text-blue-100" : "border-amber-300/20 bg-amber-300/[0.07] text-amber-100"}`}><Boxes className="mt-0.5 h-5 w-5 shrink-0" /><div><p className="font-medium">{analysis.dependency_source === "github_manifests" ? "Using committed manifests" : "Dependency inventory unavailable"}</p><p className="mt-1 opacity-70">{analysis.dependency_message}</p></div></div>}
              {analysis.vulnerability_status === "unavailable" && <div className="flex gap-3 rounded-xl border border-amber-300/20 bg-amber-300/[0.07] p-4 text-sm text-amber-100"><AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" /><div><p className="font-medium">Vulnerability access unavailable</p><p className="mt-1 text-amber-100/70">{analysis.vulnerability_message}</p></div></div>}

              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                {[
                  ["Dependencies", analysis.dependency_count, Boxes, analysis.dependency_source === "github_sbom" ? "Detected by GitHub SBOM" : analysis.dependency_source === "github_manifests" ? "Read from GitHub manifests" : "Inventory unavailable"],
                  ["Open alerts", exposures.length, ShieldAlert, analysis.vulnerability_status === "available" ? "GitHub Dependabot" : "Permission required"],
                  ["Critical", criticalCount, AlertTriangle, "Immediate attention"],
                  ["High", highCount, ShieldCheck, `Risk ${Math.round(analysis.risk.composite_score)}/100`],
                ].map(([label, value, Icon, note]) => {
                  const MetricIcon = Icon as typeof Boxes;
                  return <article key={String(label)} className="rounded-xl border border-white/[0.07] bg-card/80 p-4"><div className="flex items-center justify-between text-sm text-muted-foreground"><span>{String(label)}</span><MetricIcon className="h-4 w-4" /></div><p className="mt-3 text-3xl font-semibold">{Number(value).toLocaleString()}</p><p className="mt-1 text-xs text-muted-foreground">{String(note)}</p></article>;
                })}
              </div>

              <section className="overflow-hidden rounded-xl border border-white/[0.07] bg-card/80">
                <div className="flex items-center justify-between border-b border-white/[0.07] p-4"><div><h2 className="text-sm font-medium">Open vulnerability alerts</h2><p className="mt-1 text-xs text-muted-foreground">Directly from GitHub Dependabot</p></div><Badge variant="outline" className={riskStyles[analysis.risk.risk_level]}>{analysis.risk.risk_level} risk</Badge></div>
                {exposures.length ? <div className="overflow-x-auto"><table className="w-full min-w-[720px] text-left text-sm"><thead className="border-b border-white/[0.06] text-xs text-muted-foreground"><tr><th className="px-4 py-3 font-medium">Package</th><th className="px-4 py-3 font-medium">Ecosystem</th><th className="px-4 py-3 font-medium">Severity</th><th className="px-4 py-3 font-medium">Affected range</th><th className="px-4 py-3 font-medium">Advisory</th></tr></thead><tbody className="divide-y divide-white/[0.055]">{exposures.map((item) => <tr key={`${item.advisory_id}-${item.package_name}`}><td className="px-4 py-3 font-medium">{item.package_name}</td><td className="px-4 py-3 text-muted-foreground">{item.ecosystem}</td><td className="px-4 py-3"><Badge variant="outline" className={riskStyles[item.severity as keyof typeof riskStyles] ?? riskStyles.low}>{item.severity}</Badge></td><td className="px-4 py-3 font-mono text-xs text-muted-foreground">{item.match_reason}</td><td className="px-4 py-3 font-mono text-xs">{item.advisory_id}</td></tr>)}</tbody></table></div> : analysis.vulnerability_status === "available" ? <div className="p-8 text-center"><CheckCircle2 className="mx-auto h-8 w-8 text-emerald-300" /><p className="mt-3 text-sm font-medium">No open Dependabot alerts</p><p className="mt-1 text-xs text-muted-foreground">GitHub returned no open vulnerability alerts for this repository.</p></div> : <div className="p-8 text-center"><AlertTriangle className="mx-auto h-8 w-8 text-amber-300" /><p className="mt-3 text-sm font-medium">Alert status unknown</p><p className="mt-1 text-xs text-muted-foreground">Sentinel could not read Dependabot alerts, so this repository is not being reported as clean.</p></div>}
              </section>

              <section className="overflow-hidden rounded-xl border border-white/[0.07] bg-card/80">
                <div className="flex flex-col gap-2 border-b border-white/[0.07] p-4 sm:flex-row sm:items-center sm:justify-between"><div><h2 className="text-sm font-medium">Current dependency inventory</h2><p className="mt-1 text-xs text-muted-foreground">SPDX packages from the GitHub dependency graph</p></div><Button asChild size="sm" variant="ghost"><a href={`https://github.com/${analysis.repository}/network/dependencies`} target="_blank" rel="noreferrer">Open dependency graph <ExternalLink className="h-4 w-4" /></a></Button></div>
                <div className="overflow-x-auto"><table className="w-full min-w-[680px] text-left text-sm"><thead className="border-b border-white/[0.06] text-xs text-muted-foreground"><tr><th className="px-4 py-3 font-medium">Package</th><th className="px-4 py-3 font-medium">Version</th><th className="px-4 py-3 font-medium">Package URL</th></tr></thead><tbody className="divide-y divide-white/[0.055]">{analysis.packages.map((item, index) => <tr key={`${item.purl ?? item.name}-${index}`}><td className="px-4 py-3 font-medium">{item.name}</td><td className="px-4 py-3 font-mono text-xs text-muted-foreground">{item.version ?? "Not reported"}</td><td className="max-w-md truncate px-4 py-3 font-mono text-xs text-muted-foreground">{item.purl ?? "—"}</td></tr>)}</tbody></table></div>
                {analysis.dependency_count > analysis.packages.length && <p className="border-t border-white/[0.06] px-4 py-3 text-xs text-muted-foreground">Showing {analysis.packages.length.toLocaleString()} of {analysis.dependency_count.toLocaleString()} dependencies.</p>}
              </section>
            </>
          )}
        </section>
      </div>
    </main>
  );
}
