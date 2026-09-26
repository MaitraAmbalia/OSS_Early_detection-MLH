"use client";

import { FormEvent, useMemo, useState } from "react";
import { Activity, ArrowDownRight, ArrowUpRight, Boxes, Check, ChevronRight, CircleDot, ExternalLink, GitBranch, KeyRound, Menu, PackageSearch, Radar, RefreshCw, Search, ShieldAlert, ShieldCheck, Sparkles, Users, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";

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

const findings: Finding[] = [
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

function TrendChart() {
  const points = series.map((value, index) => `${(index / (series.length - 1)) * 100},${100 - value}`).join(" ");
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

export default function Home() {
  const [repo, setRepo] = useState("asyncapi/generator");
  const [token, setToken] = useState("");
  const [connected, setConnected] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [filter, setFilter] = useState<"all" | Finding["level"]>("all");
  const visibleFindings = useMemo(() => findings.filter((finding) => filter === "all" || finding.level === filter), [filter]);

  function analyze(event: FormEvent) {
    event.preventDefault();
    if (!repo.trim()) return;
    setAnalyzing(true);
    window.setTimeout(() => setAnalyzing(false), 750);
  }

  function connect(event: FormEvent) {
    event.preventDefault();
    if (!token.trim()) return;
    setConnected(true);
    setToken("");
  }

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
            <div className="mr-2 hidden items-center gap-2 text-xs text-muted-foreground sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300 shadow-[0_0_8px_#79f2bd]" />GH Archive · 12 min ago</div>
            <Dialog>
              <DialogTrigger asChild><Button size="sm" variant={connected ? "secondary" : "default"}>{connected ? <Check className="h-4 w-4" /> : <KeyRound className="h-4 w-4" />}{connected ? "GitHub connected" : "Connect GitHub"}</Button></DialogTrigger>
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
        <section className="mb-5 flex flex-col justify-between gap-4 lg:flex-row lg:items-end">
          <div><div className="mb-2 flex items-center gap-2 text-xs font-medium uppercase tracking-[0.16em] text-emerald-200/70"><Activity className="h-3.5 w-3.5" /> Monitoring overview</div><h1 className="text-2xl font-semibold tracking-[-0.035em] sm:text-3xl">Supply-chain risk, without the noise.</h1><p className="mt-1.5 max-w-2xl text-sm text-muted-foreground">Behavior, vulnerable dependencies, and suspicious releases correlated into one investigation queue.</p></div>
          <form onSubmit={analyze} className="flex w-full gap-2 lg:w-[430px]"><div className="relative min-w-0 flex-1"><GitBranch className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" /><Input aria-label="GitHub repository" value={repo} onChange={(e) => setRepo(e.target.value)} className="h-10 bg-black/10 pl-9" placeholder="owner/repository" /></div><Button type="submit" className="h-10" disabled={analyzing}>{analyzing ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}Analyze</Button></form>
        </section>

        <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Risk summary">
          {[
            { label: "Critical findings", value: "12", delta: "+4", note: "since yesterday", icon: ShieldAlert, color: "text-red-300", tint: "bg-red-300/10" },
            { label: "Repos monitored", value: "1,248", delta: "+38", note: "this week", icon: Boxes, color: "text-emerald-200", tint: "bg-emerald-300/10" },
            { label: "Exposed packages", value: "47", delta: "−9", note: "resolved", icon: PackageSearch, color: "text-amber-200", tint: "bg-amber-300/10" },
            { label: "Active actors", value: "326", delta: "8", note: "unusual", icon: Users, color: "text-blue-200", tint: "bg-blue-300/10" },
          ].map((metric) => (
            <article key={metric.label} className="rounded-xl border border-white/[0.07] bg-card/80 p-4 shadow-[0_14px_40px_rgb(0_0_0/12%)]"><div className="flex items-start justify-between"><p className="text-sm text-muted-foreground">{metric.label}</p><span className={`grid h-8 w-8 place-items-center rounded-lg ${metric.tint} ${metric.color}`}><metric.icon className="h-4 w-4" /></span></div><div className="mt-3 flex items-end gap-2"><span className="text-3xl font-semibold tracking-[-0.04em]">{metric.value}</span><span className={`mb-1 flex items-center text-xs ${metric.delta.startsWith("−") ? "text-emerald-300" : metric.color}`}>{metric.delta.startsWith("−") ? <ArrowDownRight className="h-3.5 w-3.5" /> : <ArrowUpRight className="h-3.5 w-3.5" />}{metric.delta}</span></div><p className="mt-1 text-xs text-muted-foreground">{metric.note}</p></article>
          ))}
        </section>

        <section className="mt-3 grid gap-3 xl:grid-cols-[minmax(0,1.55fr)_minmax(320px,.75fr)]">
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-start justify-between gap-4"><div><p className="text-sm font-medium">Risk activity</p><p className="mt-1 text-xs text-muted-foreground">Correlated signal volume · last 24 hours</p></div><div className="text-right"><p className="text-2xl font-semibold">91</p><p className="text-xs text-emerald-300">+26% from baseline</p></div></div><TrendChart /><div className="flex justify-between text-[11px] text-muted-foreground"><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span><span>Now</span></div></article>
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-center justify-between"><div><p className="text-sm font-medium">Signal distribution</p><p className="mt-1 text-xs text-muted-foreground">High-confidence detections</p></div><CircleDot className="h-4 w-4 text-muted-foreground" /></div><div className="mt-6 space-y-4">{[["Dependency exposure", 38, "bg-amber-300"], ["Actor anomalies", 27, "bg-blue-300"], ["Cross-repo burst", 21, "bg-red-300"], ["Suspicious changes", 14, "bg-violet-300"]].map(([label, value, color]) => <div key={String(label)}><div className="mb-1.5 flex justify-between text-xs"><span className="text-muted-foreground">{label}</span><span>{value}%</span></div><div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]"><div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} /></div></div>)}</div><div className="mt-6 flex items-center gap-2 rounded-lg border border-white/[0.06] bg-black/10 p-3 text-xs text-muted-foreground"><Sparkles className="h-4 w-4 shrink-0 text-emerald-200" />3 signals converged on the highest-risk incident.</div></article>
        </section>

        <section className="mt-3 overflow-hidden rounded-xl border border-white/[0.07] bg-card/80">
          <div className="flex flex-col gap-3 border-b border-white/[0.07] p-4 sm:flex-row sm:items-center sm:justify-between sm:px-5"><div><h2 className="text-sm font-medium">Investigation queue</h2><p className="mt-1 text-xs text-muted-foreground">Ranked by combined behavioral and dependency risk</p></div><div className="flex gap-1 overflow-x-auto">{(["all", "critical", "high", "medium"] as const).map((level) => <Button key={level} size="xs" variant={filter === level ? "secondary" : "ghost"} onClick={() => setFilter(level)} className="capitalize">{level}</Button>)}</div></div>
          <div className="overflow-x-auto"><table className="w-full min-w-[860px] text-left text-sm"><thead className="border-b border-white/[0.06] text-[11px] uppercase tracking-[0.12em] text-muted-foreground"><tr><th className="px-5 py-3 font-medium">Repository</th><th className="px-4 py-3 font-medium">Primary signal</th><th className="px-4 py-3 font-medium">Actor</th><th className="px-4 py-3 font-medium">Risk</th><th className="px-4 py-3 font-medium">Observed</th><th className="w-12" /></tr></thead><tbody className="divide-y divide-white/[0.055]">{visibleFindings.map((finding) => <tr key={finding.id} onClick={() => setSelected(finding)} className="cursor-pointer transition-colors hover:bg-white/[0.035]"><td className="px-5 py-3.5"><div className="font-medium">{finding.repo}</div><div className="mt-1 flex gap-1.5">{finding.tags.slice(0, 2).map((tag) => <span key={tag} className="text-[11px] text-muted-foreground">#{tag.replace(" ", "-")}</span>)}</div></td><td className="px-4 py-3.5"><div className="font-medium text-foreground/90">{finding.signal}</div><div className="mt-1 max-w-[360px] truncate text-xs text-muted-foreground">{finding.evidence}</div></td><td className="px-4 py-3.5 font-mono text-xs text-foreground/80">{finding.actor}</td><td className="px-4 py-3.5"><div className="flex items-center gap-2"><span className="w-6 font-semibold">{finding.score}</span><RiskBadge level={finding.level} /></div></td><td className="px-4 py-3.5 text-xs text-muted-foreground">{finding.time}</td><td className="pr-4"><ChevronRight className="h-4 w-4 text-muted-foreground" /></td></tr>)}</tbody></table></div>
        </section>

        <section className="mt-3 grid gap-3 pb-8 lg:grid-cols-2">
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-center justify-between"><div><h2 className="text-sm font-medium">Dependency exposure</h2><p className="mt-1 text-xs text-muted-foreground">Confirmed matches against GHSA and OSV</p></div><Button variant="ghost" size="xs">View all <ChevronRight className="h-3.5 w-3.5" /></Button></div><div className="mt-4 space-y-2">{[["lodash", "4.17.20", "Critical", "GHSA-35jh-r3h4-6jhm"], ["semver", "7.5.1", "High", "GHSA-c2qf-rxjj-qqgw"], ["aiohttp", "3.9.1", "High", "GHSA-5h86-8mv2-jq9f"]].map((dep) => <div key={dep[0]} className="flex items-center gap-3 rounded-lg border border-white/[0.055] bg-black/10 p-3"><PackageSearch className="h-4 w-4 text-amber-200" /><div className="min-w-0 flex-1"><p className="text-sm font-medium">{dep[0]} <span className="font-mono text-xs text-muted-foreground">{dep[1]}</span></p><p className="mt-0.5 truncate text-xs text-muted-foreground">{dep[3]}</p></div><span className="text-xs text-amber-200">{dep[2]}</span></div>)}</div></article>
          <article className="rounded-xl border border-white/[0.07] bg-card/80 p-4 sm:p-5"><div className="flex items-center justify-between"><div><h2 className="text-sm font-medium">Pipeline health</h2><p className="mt-1 text-xs text-muted-foreground">Freshness and coverage across sources</p></div><ShieldCheck className="h-5 w-5 text-emerald-200" /></div><div className="mt-5 grid grid-cols-3 gap-3">{[["GH Archive", "12m", "Hourly"], ["Advisories", "3h", "Daily"], ["OSV", "8h", "Daily"]].map((item) => <div key={item[0]} className="rounded-lg border border-white/[0.055] bg-black/10 p-3"><div className="mb-3 flex items-center gap-2 text-xs text-muted-foreground"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />{item[0]}</div><p className="text-xl font-semibold">{item[1]}</p><p className="mt-0.5 text-[11px] text-muted-foreground">{item[2]} refresh</p></div>)}</div></article>
        </section>
      </div>

      <Sheet open={Boolean(selected)} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto border-white/10 bg-[#0a1513] sm:max-w-lg">{selected && <><SheetHeader className="border-b border-white/[0.07] pb-5"><div className="mb-2 flex items-center gap-2"><RiskBadge level={selected.level} /><span className="font-mono text-xs text-muted-foreground">{selected.id}</span></div><SheetTitle className="text-xl">{selected.repo}</SheetTitle><SheetDescription>{selected.signal} · detected {selected.time}</SheetDescription></SheetHeader><div className="space-y-6 px-4 pb-8"><div className="rounded-xl border border-red-300/15 bg-red-300/[0.055] p-4"><p className="text-xs font-medium uppercase tracking-[0.12em] text-red-200/70">Combined risk</p><div className="mt-2 flex items-end gap-3"><span className="text-4xl font-semibold">{selected.score}</span><span className="mb-1 text-sm text-red-200">/ 100</span></div><p className="mt-3 text-sm leading-6 text-foreground/75">{selected.evidence}</p></div><div><h3 className="text-sm font-medium">Evidence timeline</h3><div className="mt-3 space-y-4 border-l border-white/10 pl-4">{[["Access changed", "Actor received repository access", "09:12"], ["First push", "Install-time script and workflow modified", "09:23"], ["Propagation", "Equivalent change reached additional repositories", "09:50"]].map((event) => <div key={event[0]} className="relative"><span className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full border-2 border-[#0a1513] bg-emerald-300" /><div className="flex justify-between gap-3"><p className="text-sm font-medium">{event[0]}</p><span className="text-xs text-muted-foreground">{event[2]}</span></div><p className="mt-1 text-xs text-muted-foreground">{event[1]}</p></div>)}</div></div><div><h3 className="text-sm font-medium">Signals fired</h3><div className="mt-3 flex flex-wrap gap-2">{selected.tags.map((tag) => <Badge key={tag} variant="secondary">{tag}</Badge>)}</div></div><div className="grid grid-cols-2 gap-3"><Button variant="secondary"><X className="h-4 w-4" />Dismiss</Button><Button><ExternalLink className="h-4 w-4" />Open on GitHub</Button></div></div></>}</SheetContent>
      </Sheet>
    </main>
  );
}
