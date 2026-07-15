import { createFileRoute, Link } from "@tanstack/react-router";
import { motion } from "framer-motion";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  RadialBarChart, RadialBar, PolarAngleAxis,
} from "recharts";
import {
  Activity, AlertTriangle, ShieldCheck, Database, FolderSearch,
  ChevronRight, PlayCircle, Cpu, ScrollText, HardDrive,
} from "lucide-react";
import {
  summaryStats, caseInfo, timelineData, activityFeed,
  antiForensicEvents, clusters,
} from "../lib/mockData";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — Artifact-Pulse" },
      { name: "description", content: "Live forensic triage dashboard with case health, anomalies, anti-forensic alerts, and pipeline activity." },
    ],
  }),
  component: DashboardHome,
});

function DashboardHome() {
  const sev = {
    critical: antiForensicEvents.filter(e => e.severity === "critical").length + 4,
    high: 11,
    medium: 6,
    low: 22,
  };
  return (
    <div className="mx-auto max-w-[1500px] space-y-6">
      <PageHeader
        title="Operations Dashboard"
        subtitle="Active case triage · cross-layer evidence health · live pipeline feed"
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <KpiCard icon={FolderSearch} label="Active Investigations" value="3" sub="2 sealed · 1 in triage" tone="primary" />
        <KpiCard icon={Database} label="Artifacts Processed" value={summaryStats.artifactsExtracted.toLocaleString()} sub="across 4 layers" tone="accent" />
        <KpiCard
          icon={AlertTriangle}
          label="Anomalies Detected"
          value={`${sev.critical + sev.high + sev.medium + sev.low}`}
          sub={`${sev.critical} crit · ${sev.high} high · ${sev.medium} med`}
          tone="critical"
        />
        <KpiCard icon={ShieldCheck} label="Chain of Custody" value="INTACT" sub="14,782 / 14,782 verified" tone="primary" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <RiskGauge score={summaryStats.overallSuspicion} />
        <SeverityCard sev={sev} />
        <CaseInfoCard />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2" title="Cross-Layer Suspicion Timeline" subtitle="5-min rolling window · weighted ensemble score" right={<LegendDot color="oklch(0.82 0.18 155)" label="suspicion" />}>
          <div className="h-72 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 14, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="gA" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="oklch(0.82 0.18 155)" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="oklch(0.82 0.18 155)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.28 0.016 240)" />
                <XAxis dataKey="time" stroke="oklch(0.62 0.018 220)" fontSize={11} fontFamily="JetBrains Mono" />
                <YAxis stroke="oklch(0.62 0.018 220)" fontSize={11} fontFamily="JetBrains Mono" domain={[0, 100]} />
                <Tooltip contentStyle={tt} />
                <Area type="monotone" dataKey="score" stroke="oklch(0.82 0.18 155)" fill="url(#gA)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <ActivityFeed />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Top Suspicion Clusters" subtitle="KMeans + Isolation Forest ensemble" right={<Link to="/anomalies" className="font-mono text-[10px] uppercase tracking-wider text-primary hover:underline">view all →</Link>}>
          <ul className="space-y-2">
            {clusters.slice(0, 5).map((c) => (
              <li key={c.id} className="flex items-center gap-3 rounded border border-border/60 bg-card/40 p-3">
                <div className="font-mono text-[11px] text-primary">{c.id}</div>
                <div className="min-w-0 flex-1 truncate text-xs text-foreground">{c.pattern}</div>
                <div className="font-mono text-[11px] text-muted-foreground">{c.artifactCount} arts</div>
                <ScoreBar value={c.suspicionScore} />
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Quick Actions" subtitle="Pipeline shortcuts">
          <div className="grid gap-2">
            <ActionLink to="/pipeline" icon={PlayCircle} label="Run new pipeline" sub="kick off extraction on endpoint" />
            <ActionLink to="/artifacts" icon={Database} label="Explore artifacts" sub="14,782 indexed · sortable" />
            <ActionLink to="/anti-forensic" icon={AlertTriangle} label="Anti-forensic alerts" sub="4 flagged techniques" />
            <ActionLink to="/chain" icon={ShieldCheck} label="Verify chain" sub="ledger integrity check" />
          </div>
        </Panel>

        <Panel title="Layer Throughput" subtitle="Artifacts per source">
          <ul className="space-y-3 font-mono text-xs">
            <ThroughputRow icon={HardDrive} label="Filesystem" value={summaryStats.filesScanned} total={summaryStats.artifactsExtracted} color="oklch(0.82 0.18 155)" />
            <ThroughputRow icon={ScrollText} label="Event Logs" value={summaryStats.eventsParsed} total={summaryStats.artifactsExtracted} color="oklch(0.78 0.14 210)" />
            <ThroughputRow icon={Cpu} label="Process" value={summaryStats.processesAnalyzed} total={summaryStats.artifactsExtracted} color="oklch(0.80 0.17 75)" />
            <ThroughputRow icon={Database} label="Registry" value={summaryStats.registryKeys} total={summaryStats.artifactsExtracted} color="oklch(0.68 0.18 295)" />
          </ul>
        </Panel>
      </div>
    </div>
  );
}

const tt = {
  background: "oklch(0.19 0.014 240)",
  border: "1px solid oklch(0.28 0.016 240)",
  borderRadius: 4,
  fontFamily: "JetBrains Mono",
  fontSize: 11,
};

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="flex flex-wrap items-end justify-between gap-3 border-b border-border/60 pb-4">
      <div>
        <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-primary">// {caseInfo.caseId}</div>
        <h1 className="mt-1 font-mono text-2xl font-bold tracking-tight md:text-3xl">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {action}
    </motion.div>
  );
}

function KpiCard({
  icon: Icon, label, value, sub, tone,
}: { icon: typeof Activity; label: string; value: string; sub: string; tone: "primary" | "accent" | "critical" }) {
  const toneCls = {
    primary: "border-primary/30 text-primary",
    accent: "border-accent/30 text-accent",
    critical: "border-destructive/40 text-destructive glow-critical",
  }[tone];
  return (
    <div className={`group relative overflow-hidden rounded-md border bg-card/40 p-5 transition-colors hover:bg-card/60 ${toneCls}`}>
      <div className="flex items-center justify-between">
        <Icon className="h-4 w-4" />
        <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{sub}</span>
      </div>
      <div className="mt-4 font-mono text-3xl font-bold">{value}</div>
      <div className="mt-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );
}

function RiskGauge({ score }: { score: number }) {
  const data = [{ name: "score", value: score, fill: score > 80 ? "oklch(0.64 0.24 25)" : score > 50 ? "oklch(0.80 0.17 75)" : "oklch(0.82 0.18 155)" }];
  return (
    <Panel title="Case Risk Score" subtitle="Composite ensemble · 0–100">
      <div className="relative h-48 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart innerRadius="70%" outerRadius="100%" data={data} startAngle={210} endAngle={-30}>
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
            <RadialBar dataKey="value" cornerRadius={4} background={{ fill: "oklch(0.22 0.014 240)" }} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <div className="font-mono text-5xl font-bold text-destructive">{score}</div>
          <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">critical</div>
        </div>
      </div>
    </Panel>
  );
}

function SeverityCard({ sev }: { sev: { critical: number; high: number; medium: number; low: number } }) {
  const rows = [
    { label: "critical", value: sev.critical, color: "oklch(0.64 0.24 25)" },
    { label: "high",     value: sev.high,     color: "oklch(0.80 0.17 75)" },
    { label: "medium",   value: sev.medium,   color: "oklch(0.78 0.14 210)" },
    { label: "low",      value: sev.low,      color: "oklch(0.62 0.018 220)" },
  ];
  const max = Math.max(...rows.map(r => r.value));
  return (
    <Panel title="Anomaly Severity" subtitle="Breakdown of flagged events">
      <ul className="space-y-3">
        {rows.map(r => (
          <li key={r.label} className="font-mono text-xs">
            <div className="flex items-baseline justify-between">
              <span className="uppercase tracking-wider text-muted-foreground">{r.label}</span>
              <span style={{ color: r.color }}>{r.value}</span>
            </div>
            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
              <div className="h-full rounded-full" style={{ width: `${(r.value / max) * 100}%`, background: r.color }} />
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function CaseInfoCard() {
  return (
    <Panel title="Current Case" subtitle="Acquisition metadata">
      <dl className="space-y-2.5 font-mono text-xs">
        <Row k="case_id" v={caseInfo.caseId} highlight />
        <Row k="host" v={caseInfo.hostName} />
        <Row k="os" v={caseInfo.os} />
        <Row k="examiner" v={caseInfo.examiner} />
        <Row k="acquired" v={new Date(caseInfo.acquisitionDate).toLocaleString()} />
        <Row k="master_hash" v={caseInfo.masterHash.slice(0, 24) + "…"} mono />
      </dl>
    </Panel>
  );
}
function Row({ k, v, highlight, mono }: { k: string; v: string; highlight?: boolean; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/40 pb-2 last:border-0">
      <span className="text-muted-foreground">{k}</span>
      <span className={`truncate text-right ${highlight ? "text-primary" : ""} ${mono ? "text-accent" : ""}`}>{v}</span>
    </div>
  );
}

function ActivityFeed() {
  return (
    <Panel title="Live Pipeline Feed" subtitle="stdout · tail -f engine.log" right={<LegendDot color="oklch(0.82 0.18 155)" label="streaming" pulse />}>
      <div className="h-72 overflow-y-auto rounded border border-border/60 bg-background/60 p-3 font-mono text-[11px]">
        {activityFeed.map((l, i) => {
          const c = l.level === "crit" ? "text-destructive" : l.level === "warn" ? "text-[oklch(0.80_0.17_75)]" : "text-muted-foreground";
          return (
            <div key={i} className="terminal-feed-line flex gap-2 py-0.5">
              <span className="shrink-0 text-muted-foreground">{l.ts}</span>
              <span className={`shrink-0 uppercase ${c}`}>{l.level.padEnd(4, " ")}</span>
              <span className="text-foreground">{l.msg}</span>
            </div>
          );
        })}
        <div className="text-primary blink-caret" />
      </div>
    </Panel>
  );
}

function ScoreBar({ value }: { value: number }) {
  const color = value >= 90 ? "oklch(0.64 0.24 25)" : value >= 75 ? "oklch(0.80 0.17 75)" : "oklch(0.78 0.14 210)";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1 w-20 overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${value}%`, background: color }} />
      </div>
      <span className="w-7 text-right font-mono text-[11px]" style={{ color }}>{value}</span>
    </div>
  );
}

function ActionLink({ to, icon: Icon, label, sub }: { to: any; icon: typeof Activity; label: string; sub: string }) {
  return (
    <Link to={to} className="group flex items-center gap-3 rounded border border-border/60 bg-card/40 p-3 transition-colors hover:border-primary/40 hover:bg-card/70">
      <div className="flex h-9 w-9 items-center justify-center rounded border border-primary/30 bg-primary/10 text-primary">
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="font-mono text-xs text-foreground">{label}</div>
        <div className="font-mono text-[10px] text-muted-foreground">{sub}</div>
      </div>
      <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
    </Link>
  );
}

function ThroughputRow({ icon: Icon, label, value, total, color }: { icon: typeof Activity; label: string; value: number; total: number; color: string }) {
  const pct = (value / total) * 100;
  return (
    <li>
      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5" style={{ color }} />
        <span className="text-muted-foreground">{label}</span>
        <span className="ml-auto text-foreground">{value.toLocaleString()}</span>
      </div>
      <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full" style={{ width: `${pct}%`, background: color }} />
      </div>
    </li>
  );
}

export function Panel({
  title, subtitle, right, children, className = "",
}: { title: string; subtitle?: string; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={`rounded-md border border-border/60 bg-card/30 ${className}`}>
      <header className="flex items-start justify-between gap-3 border-b border-border/60 px-5 py-3">
        <div>
          <h3 className="font-mono text-xs font-bold uppercase tracking-[0.16em] text-foreground">{title}</h3>
          {subtitle && <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">{subtitle}</p>}
        </div>
        {right}
      </header>
      <div className="p-5">{children}</div>
    </section>
  );
}

export function LegendDot({ color, label, pulse }: { color: string; label: string; pulse?: boolean }) {
  return (
    <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
      <span className={`h-1.5 w-1.5 rounded-full ${pulse ? "pulse-dot" : ""}`} style={{ background: color }} />
      {label}
    </div>
  );
}
