"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import { Activity, ArrowDownRight, ArrowUpRight, Boxes, Check, ChevronRight, CircleDot, ExternalLink, GitBranch, KeyRound, Menu, PackageSearch, Radar, RefreshCw, Search, ShieldAlert, ShieldCheck, Sparkles, Users, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { api, ApiOverview, RepositoryAnalysis } from "@/lib/api";

type Finding = {
  id: string;
  repo: string;
  actor: string;
  score: number;
  level: "critical" | "high" | "medium";
  signal: string;
  evidence: string;
  time: string;
  tags: string[];
};

const fallbackFindings: Finding[] = [
  { id: "evt_0187", repo: "asyncapi/generator", actor: "release-helper", score: 96, level: "critical", signal: "Cross-repo propagation", evidence: "Same install-time change reached 14 repositories in 38 minutes.", time: "8 min ago", tags: ["postinstall", "14 repos", "new actor"] },
  { id: "evt_0184", repo: "acme/checkout-sdk", actor: "dmitry-k", score: 87, level: "high", signal: "New collaborator → push", evidence: "First push landed 11 minutes after repository access was granted.", time: "24 min ago", tags: ["first push", "default branch"] },
  { id: "evt_0179", repo: "northstar/web-client", actor: "dependabot[bot]", score: 74, level: "high", signal: "Dependency exposure", evidence: "Build resolves a version covered by a reviewed critical advisory.", time: "1 hr ago", tags: ["npm", "GHSA", "direct dep"] },
  { id: "evt_0172", repo: "oss-labs/auth-proxy", actor: "ci-release", score: 61, level: "medium", signal: "Workflow permission change", evidence: "Release workflow added id-token write access and an external action.", time: "3 hr ago", tags: ["OIDC", "workflow"] },
];

const series = [18, 22, 17, 28, 25, 34, 29, 43, 38, 55, 49, 71, 62, 82, 76, 91];

function RiskBadge({ level }: { level: Finding["level"] }) {
  const styles = { critical: "border-red-400/25 bg-red-400/10 text-red-300", high: "border-amber-300/25 bg-amber-300/10 text-amber-200", medium: "border-blue-300/25 bg-blue-300/10 text-blue-200" };
  return <Badge variant="outline" className={`capitalize ${styles[level]}`}>{level}</Badge>;
}

function TrendChart({ values }: { values: number[] }) {
  const chartValues = values.length > 1 ? values : series;
  const points = chartValues.map((value, index) => `${(index / (chartValues.length - 1)) * 100},${100 - value}`).join(" ");
  return (
    <div className="relative h-44 overflow-hidden" aria-label="Risk activity increased over the last 24 hours">
      <div className="absolute inset-0 grid grid-rows-4">{[0, 1, 2, 3].map((row) => <span key={row} className="border-t border-white/[0.055]" />)}</div>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 h-full w-full" role="img">
        <defs><linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#79f2bd" stopOpacity="0.28" /><stop offset="100%" stopColor="#79f2bd" stopOpacity="0" /></linearGradient></defs>
        <polygon points={`0,100 ${points} 100,100`} fill="url(#riskFill)" />
        <polyline points={points} fill="none" stroke="#79f2bd" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="absolute right-[5%] top-[7%] h-2.5 w-2.5 rounded-full border-2 border-[#07100f] bg-[#79f2bd] shadow-[0_0_0_4px_rgb(121_242_189/14%)]" />
    </div>
  );
}

function freshness(timestamp: string | null) {
  if (!timestamp) return "—";
  const minutes = Math.max(0, Math.round((Date.now() - new Date(timestamp).getTime()) / 60000));
  return minutes < 60 ? `${minutes}m` : `${Math.round(minutes / 60)}h`;
}

export default function Home() {
  const [repo, setRepo] = useState("asyncapi/generator");
  const [token, setToken] = useState("");
  const [connected, setConnected] = useState(false);
  const [identity, setIdentity] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [overview, setOverview] = useState<ApiOverview | null>(null);
  const [findings, setFindings] = useState<Finding[]>(fallbackFindings);
  const [analysis, setAnalysis] = useState<RepositoryAnalysis | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filter, setFilter] = useState<"all" | Finding["level"]>("all");
  const visibleFindings = useMemo(
    () => findings.filter((finding) => filter === "all" || finding.level === filter),
    [filter, findings],
  );

  useEffect(() => {
    Promise.all([api.overview(), api.findings()])
      .then(([nextOverview, page]) => {
        setOverview(nextOverview);
        setFindings(page.items.map((item) => ({
          id: item.risk_id,
          repo: item.repo_name,
          actor: item.actor_login,
          score: Math.round(item.composite_score),
          level: item.risk_level === "low" ? "medium" : item.risk_level,
          signal: item.primary_signal.replaceAll("_", " "),
          evidence: item.evidence,
          time: new Date(item.latest_activity).toLocaleString(),
          tags: item.signals_fired,
        })));
      })
      .catch(() => setError("Backend unavailable — showing representative demo data."));
  }, []);

  async function analyze(event: FormEvent) {
    event.preventDefault();
    const normalized = repo.trim().replace(/^https?:\/\/github\.com\//, "").replace(/\/$/, "");
    if (!/^[^/]+\/[^/]+$/.test(normalized)) {
      setError("Enter a repository as owner/name.");
      return;
    }
    setAnalyzing(true);
    setError("");
    try {
      setAnalysis(await api.analyze(normalized, token || undefined));
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  }

  async function connect(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) return;
    setError("");
    try {
      const result = await api.validateToken(token.trim());
      setIdentity(result.login);
      setConnected(true);
    } catch (requestError) {
      setConnected(false);
      setError(requestError instanceof Error ? requestError.message : "Token validation failed");
    }
  }

  const metricIcons = [ShieldAlert, Boxes, PackageSearch, Users];
  const metricColors = ["text-red-300", "text-emerald-200", "text-amber-200", "text-blue-200"];
  const metrics = overview?.metrics ?? [
    { label: "Critical findings", value: 12, delta: 4, note: "since yesterday" },
    { label: "Repos monitored", value: 1248, delta: 38, note: "this week" },
    { label: "Exposed packages", value: 47, delta: -9, note: "resolved" },
    { label: "Active actors", value: 326, delta: 8, note: "unusual" },
  ];
  const signalRows = overview?.signal_distribution.map((item, index) => ({
    label: item.signal.replaceAll("_", " "),
    value: item.percentage,
    color: ["bg-amber-300", "bg-blue-300", "bg-red-300", "bg-violet-300"][index % 4],
  })) ?? [
    { label: "Dependency exposure", value: 38, color: "bg-amber-300" },
    { label: "Actor anomalies", value: 27, color: "bg-blue-300" },
    { label: "Cross-repo burst", value: 21, color: "bg-red-300" },
    { label: "Suspicious changes", value: 14, color: "bg-violet-300" },
  ];
  const pipelineRows = overview?.pipeline.map((item) => ({
    label: item.source.replaceAll("_", " "),
    age: freshness(item.last_success_at),
    cadence: item.cadence,
    healthy: item.status === "healthy",
  })) ?? [
    { label: "GH Archive", age: "12m", cadence: "Hourly", healthy: true },
    { label: "Advisories", age: "3h", cadence: "Daily", healthy: true },
    { label: "OSV", age: "8h", cadence: "Daily", healthy: true },
  ];
  const exposureRows = analysis?.risk.dependency_exposures.length
    ? analysis.risk.dependency_exposures.map((item) => ({
        name: item.package_name,
        version: item.resolved_version ?? "unknown",
        severity: item.severity,
        advisory: item.advisory_id,
      }))
    : [
        { name: "lodash", version: "4.17.20", severity: "Critical", advisory: "GHSA-35jh-r3h4-6jhm" },
        { name: "semver", version: "7.5.1", severity: "High", advisory: "GHSA-c2qf-rxjj-qqgw" },
        { name: "aiohttp", version: "3.9.1", severity: "High", advisory: "GHSA-5h86-8mv2-jq9f" },
      ];

  return (
    <main className="min-h-screen text-foreground">
      <header className="sticky top-0 z-30 border-b border-white/[0.07] bg-[#07100f]/90 backdrop-blur-xl">
        <div className="mx-auto flex h-16 max-w-[1540px] items-center gap-4 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-emerald-300/20 bg-emerald-300/10 text-emerald-200"><Radar className="h-[18px] w-[18px]" /></div>
            <div><p className="text-[15px] font-semibold leading-none tracking-tight">Sentinel OSS</p><p className="mt-1 text-[11px] leading-none text-muted-foreground">Supply-chain intelligence</p></div>
          </div>
          <nav className="ml-8 hidden items-center gap-1 md:flex" aria-label="Primary navigation">
            <Button variant="ghost" size="sm" className="bg-white/[0.06] text-foreground">Overview</Button>
            <Button variant="ghost" size="sm" className="text-muted-foreground">Dependencies</Button>
            <Button variant="ghost" size="sm" className="text-muted-foreground">Activity</Button>
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <div className="mr-2 hidden items-center gap-2 text-xs text-muted-foreground sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_8px_#79f2bd]" />{overview ? "API connected" : "Demo data"}</div>
            <Dialog>
              <DialogTrigger asChild><Button size="sm" variant={connected ? "secondary" : "default"}>{connected ? <Check className="h-4 w-4" /> : <KeyRound className="h-4 w-4" />}{connected ? `Connected: ${identity}` : "Connect GitHub"}</Button></DialogTrigger>
              <DialogContent className="border-white/10 bg-[#0b1715] sm:max-w-md">
                <DialogHeader><DialogTitle>Connect GitHub for repository analysis</DialogTitle><DialogDescription>Use a fine-grained, read-only token. This prototype keeps it only in memory for the current session.</DialogDescription></DialogHeader>
                <form onSubmit={connect} className="space-y-4 pt-2">
                  <div className="space-y-2"><label htmlFor="github-token" className="text-sm font-medium">Personal access token</label><Input id="github-token" type="password" autoComplete="off" placeholder="github_pat_••••••••" value={token} onChange={(e) => setToken(e.target.value)} /></div>
                  <div className="rounded-lg border border-emerald-300/15 bg-emerald-300/[0.05] p-3 text-xs leading-5 text-emerald-100/70">Recommended permission: repository contents read-only. Never grant write or administration access for analysis.</div>
                  <Button type="submit" className="w-full" disabled={!token.trim()}>Connect securely</Button>
                </form>
              </DialogContent>
            </Dialog>
            <Button size="icon-sm" variant="ghost" className="md:hidden"><Menu className="h-4 w-4" /><span className="sr-only">Open menu</span></Button>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1540px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7">
        {error && <div className="mb-4 rounded-lg border border-amber-300/20 bg-amber-300/[0.07] px-4 py-3 text-sm text-amber-100">{error}</div>}
        {analysis && <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-emerald-300/20 bg-emerald-300/[0.06] px-4 py-3 text-sm"><span><strong>{analysis.repository}</strong> analyzed: {analysis.dependency_count} dependencies across {analysis.ecosystems.join(", ") || "unknown ecosystems"}.</span><Badge variant="secondary">Risk {Math.round(analysis.risk.composite_score)}/100</Badge></div>}
        <section className="mb-5 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div><div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-emerald-200/70"><Activity className="h-3.5 w-3.5" /> Monitoring overview</div><h1 className="text-2xl font-semibold tracking-[-0.035em] sm:text-3xl">Supply-chain risk, without the noise.</h1><p className="mt-1.5 max-w-2xl text-sm text-muted-foreground">Behavior, vulnerable dependencies, and suspicious releases correlated into one investigation queue.</p></div>
          <form onSubmit={analyze} className="flex w-full gap-2 lg:w-[430px]"><div className="relative min-w-0 flex-1"><GitBranch className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="GitHub repository" value={repo} onChange={(e) => setRepo(e.target.value)} className="h-10 bg-black/10 pl-9" placeholder="owner/repository" /></div><Button type="submit" className="h-10" disabled={analyzing}>{analyzing ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}Analyze</Button></form>
        </section>

        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Risk summary">
          {metrics.map((metric, index) => {
            const Icon = metricIcons[index] ?? Activity;
            const color = metricColors[index] ?? "text-emerald-200";
            return (
            <article key={metric.label} className="rounded-xl border border-white/[0.07] bg-card/80 p-4 shadow-[0_14px_40px_rgb(0_0_0/12%)]"><div className="flex items-start justify-between"><p className="text-sm text-muted-foreground">{metric.label}</p><span className={`grid h-8 w-8 place-items-center rounded-lg bg-white/[0.05] ${color}`}><Icon className="h-4 w-4" /></span></div><div className="mt-3 flex items-end gap-2"><span className="text-3xl font-semibold tracking-[-0.04em]">{metric.value.toLocaleString()}</span><span className={`mb-1 flex items-center text-xs ${metric.delta < 0 ? "text-emerald-300" : color}`}>{metric.delta < 0 ? <ArrowDownRight className="h-3.5 w-3.5" /> : <ArrowUpRight className="h-3.5 w-3.5" />}{metric.delta > 0 ? "+" : ""}{metric.delta}</span></div><p className="mt-1 text-xs text-muted-foreground">{metric.note}</p></article>
            );
          })}
        </section>

        <section className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,.75fr)]">
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-start justify-between gap-4"><div><p className="text-sm font-medium">Risk activity</p><p className="mt-1 text-xs text-muted-foreground">Correlated signal volume · last 24 hours</p></div><div className="text-right"><p className="text-2xl font-semibold">{Math.round(overview?.trend.at(-1)?.score ?? 91)}</p><p className="text-xs text-emerald-300">latest score</p></div></div><TrendChart values={overview?.trend.map((point) => point.score) ?? series} /><div className="flex justify-between text-[11px] text-muted-foreground"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>Now</span></div></article>
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5">
            <div className="flex items-center justify-between"><div><p className="text-sm font-medium">Signal distribution</p><p className="mt-1 text-xs text-muted-foreground">High-confidence detections</p></div><CircleDot className="h-4 w-4 text-muted-foreground" /></div>
            <div className="mt-6 space-y-4">
              {signalRows.map((item) => (
                <div key={item.label}>
                  <div className="mb-1.5 flex justify-between text-xs"><span className="capitalize text-muted-foreground">{item.label}</span><span>{item.value}%</span></div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={`h-full rounded-full ${item.color}`} style={{ width: `${item.value}%` }} /></div>
                </div>
              ))}
            </div>
            <div className="mt-6 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-black/10 p-3 text-xs text-muted-foreground"><Sparkles className="h-4 w-4 shrink-0 text-emerald-200" />Correlated evidence is ranked by combined confidence.</div>
          </article>
        </section>

        <section className="mt-3 overflow-hidden rounded-xl border border-white/[0.07] bg-card/80">
          <div className="flex flex-col gap-3 border-b border-white/[0.07] p-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"><div><h2 className="text-sm font-medium">Investigation queue</h2><p className="mt-1 text-xs text-muted-foreground">Ranked by combined behavioral and dependency risk</p></div><div className="flex gap-1 overflow-x-auto">{(["all", "critical", "high", "medium"] as const).map((level) => <Button key={level} size="xs" variant={filter === level ? "secondary" : "ghost"} onClick={() => setFilter(level)} className="capitalize">{level}</Button>)}</div></div>
          <div className="overflow-x-auto"><table className="w-full min-w-[860px] text-left text-sm"><thead className="border-b border-white/[0.06] text-[11px] uppercase tracking-[0.12em] text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Repository</th><th className="px-4 py-3 font-medium">Primary signal</th><th className="px-4 py-3 font-medium">Actor</th><th className="px-4 py-3 font-medium">Risk</th><th className="px-4 py-3 font-medium">Observed</th><th className="w-12" /></tr></thead><tbody className="divide-y divide-white/[0.055]">{visibleFindings.map((finding) => <tr key={finding.id} onClick={() => setSelected(finding)} className="cursor-pointer transition-colors hover:bg-white/[0.035]"><td className="px-5 py-3.5"><div className="font-medium">{finding.repo}</div><div className="mt-1 flex gap-1.5">{finding.tags.slice(0, 2).map((tag) => <span key={tag} className="text-[11px] text-muted-foreground">#{tag.replace(" ", "-")}</span>)}</div></td><td className="px-4 py-3.5"><div className="font-medium text-foreground/90">{finding.signal}</div><div className="mt-1 max-w-[360px] truncate text-xs text-muted-foreground">{finding.evidence}</div></td><td className="px-4 py-3.5 font-mono text-xs text-foreground/80">{finding.actor}</td><td className="px-4 py-3.5"><div className="flex items-center gap-2"><span className="w-6 font-semibold">{finding.score}</span><RiskBadge level={finding.level} /></div></td><td className="px-4 py-3.5 text-xs text-muted-foreground">{finding.time}</td><td className="pr-4"><ChevronRight className="h-4 w-4 text-muted-foreground" /></td></tr>)}</tbody></table></div>
        </section>

        <section className="mt-3 grid gap-3 pb-8 lg:grid-cols-2">
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-center justify-between"><div><h2 className="text-sm font-medium">Dependency exposure</h2><p className="mt-1 text-xs text-muted-foreground">Confirmed matches against GHSA and OSV</p></div><Button variant="ghost" size="xs">View all <ChevronRight className="h-3.5 w-3.5" /></Button></div><div className="mt-4 space-y-2">{exposureRows.slice(0, 3).map((dep) => <div key={`${dep.name}-${dep.advisory}`} className="flex items-center gap-3 rounded-lg border border-white/[0.055] bg-black/10 p-3"><PackageSearch className="h-4 w-4 text-amber-200" /><div className="min-w-0 flex-1"><p className="text-sm font-medium">{dep.name} <span className="font-mono text-xs text-muted-foreground">{dep.version}</span></p><p className="mt-0.5 truncate text-xs text-muted-foreground">{dep.advisory}</p></div><span className="capitalize text-xs text-amber-200">{dep.severity}</span></div>)}</div></article>
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-center justify-between"><div><h2 className="text-sm font-medium">Pipeline health</h2><p className="mt-1 text-xs text-muted-foreground">Freshness and coverage across sources</p></div><ShieldCheck className="h-5 w-5 text-emerald-200" /></div><div className="mt-5 grid grid-cols-3 gap-3">{pipelineRows.map((item) => <div key={item.label} className="rounded-lg border border-white/[0.055] bg-black/10 p-3"><div className="mb-3 flex items-center gap-2 text-xs capitalize text-muted-foreground"><span className={`h-1.5 w-1.5 rounded-full ${item.healthy ? "bg-emerald-300" : "bg-amber-300"}`} />{item.label}</div><p className="text-xl font-semibold">{item.age}</p><p className="mt-0.5 text-[11px] capitalize text-muted-foreground">{item.cadence} refresh</p></div>)}</div></article>
        </section>
      </div>

      <Sheet open={Boolean(selected)} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto border-white/10 bg-[#0a1513] sm:max-w-lg">{selected && <><SheetHeader className="border-b border-white/[0.07] pb-5"><div className="mb-2 flex items-center gap-2"><RiskBadge level={selected.level} /><span className="font-mono text-xs text-muted-foreground">{selected.id}</span></div><SheetTitle className="text-xl">{selected.repo}</SheetTitle><SheetDescription>{selected.signal} · detected {selected.time}</SheetDescription></SheetHeader><div className="space-y-6 px-4 pb-8"><div className="rounded-xl border border-red-300/15 bg-red-300/[0.055] p-4"><p className="text-xs font-medium uppercase tracking-[0.12em] text-red-200/70">Combined risk</p><div className="mt-2 flex items-end gap-3"><span className="text-4xl font-semibold">{selected.score}</span><span className="mb-1 text-sm text-red-200">/ 100</span></div><p className="mt-3 text-sm leading-6 text-foreground/75">{selected.evidence}</p></div><div><h3 className="text-sm font-medium">Evidence timeline</h3><div className="mt-3 space-y-4 border-l border-white/10 pl-4">{[["Access changed", "Actor received repository access", "09:12"], ["First push", "Install-time script and workflow modified", "09:23"], ["Propagation", "Equivalent change reached additional repositories", "09:50"]].map((event) => <div key={event[0]} className="relative"><span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-[#0a1513] bg-emerald-300" /><div className="flex justify-between gap-3"><p className="text-sm font-medium">{event[0]}</p><span className="text-xs text-muted-foreground">{event[2]}</span></div><p className="mt-1 text-xs text-muted-foreground">{event[1]}</p></div>)}</div></div><div><h3 className="text-sm font-medium">Signals fired</h3><div className="mt-3 flex flex-wrap gap-2">{selected.tags.map((tag) => <Badge key={tag} variant="secondary">{tag}</Badge>)}</div></div><div className="grid grid-cols-2 gap-3"><Button variant="secondary"><X className="h-4 w-4" />Dismiss</Button><Button><ExternalLink className="h-4 w-4" />Open on GitHub</Button></div></div></>}</SheetContent>
      </Sheet>
    </main>
  );
}
