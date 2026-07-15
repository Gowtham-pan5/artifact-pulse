import { createFileRoute } from "@tanstack/react-router";
import { ShieldAlert, Eraser, Trash2, Clock, FileX } from "lucide-react";
import { PageHeader, Panel } from "./index";
import { antiForensicEvents, type Severity } from "../lib/mockData";

export const Route = createFileRoute("/anti-forensic")({
  head: () => ({ meta: [{ title: "Anti-Forensic Alerts — Artifact-Pulse" }] }),
  component: AntiForensicPage,
});

const ICON_BY_TECHNIQUE: Record<string, typeof ShieldAlert> = {
  "Wiping Tool Execution": Eraser,
  "Audit Log Clearing": FileX,
  "Recycle Bin Wipe": Trash2,
  "Timestomping": Clock,
};

const MITRE: Record<string, { id: string; name: string }> = {
  "Wiping Tool Execution": { id: "T1070.004", name: "File Deletion" },
  "Audit Log Clearing": { id: "T1070.001", name: "Clear Windows Event Logs" },
  "Recycle Bin Wipe": { id: "T1070.004", name: "File Deletion" },
  "Timestomping": { id: "T1070.006", name: "Timestomp" },
};

function AntiForensicPage() {
  const crit = antiForensicEvents.filter(e => e.severity === "critical").length;
  const high = antiForensicEvents.filter(e => e.severity === "high").length;

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <PageHeader
        title="Anti-Forensic Alerts"
        subtitle="Detection of wiping tools · log clearing · timestomping · VSS deletion"
      />

      <div className="grid gap-4 md:grid-cols-3">
        <Banner level="critical" count={crit} label="critical techniques" />
        <Banner level="high" count={high} label="high-confidence indicators" />
        <Banner level="info" count={antiForensicEvents.length} label="total alerts in window" />
      </div>

      <div className="space-y-3">
        {antiForensicEvents.map((e, i) => {
          const Icon = ICON_BY_TECHNIQUE[e.technique] ?? ShieldAlert;
          const mitre = MITRE[e.technique];
          return (
            <div
              key={e.id}
              className={`relative overflow-hidden rounded-md border bg-card/40 p-5 ${e.severity === "critical" ? "border-destructive/50 glow-critical" : "border-border/60"}`}
            >
              <div className="absolute left-0 top-0 h-full w-1" style={{ background: e.severity === "critical" ? "oklch(0.64 0.24 25)" : "oklch(0.80 0.17 75)" }} />
              <div className="flex items-start gap-4">
                <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded border ${e.severity === "critical" ? "border-destructive/40 bg-destructive/10 text-destructive" : "border-[oklch(0.80_0.17_75_/_0.4)] bg-[oklch(0.80_0.17_75_/_0.1)] text-[oklch(0.80_0.17_75)]"}`}>
                  <Icon className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">{e.id}</span>
                    <h3 className="font-mono text-base font-bold text-foreground">{e.technique}</h3>
                    <SeverityTag sev={e.severity} />
                    {mitre && (
                      <span className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
                        ATT&amp;CK · {mitre.id} {mitre.name}
                      </span>
                    )}
                  </div>
                  <p className="mt-2 font-mono text-xs text-muted-foreground">
                    <span className="text-foreground">evidence: </span>{e.evidence}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-muted-foreground">
                    <span><span className="text-foreground">timestamp </span>{new Date(e.timestamp).toISOString()}</span>
                    <span><span className="text-foreground">source </span>antiforensic_detector.py</span>
                    <span><span className="text-foreground">confidence </span><span className="text-accent">{e.severity === "critical" ? "0.98" : "0.84"}</span></span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <Panel title="Detection Heuristics" subtitle="How antiforensic_detector.py classifies these techniques">
        <ul className="grid gap-3 font-mono text-xs md:grid-cols-2">
          <Heur title="Wiping Tool Signatures" body="Prefetch entries for CCleaner / BleachBit / Eraser cross-referenced against known SHA-256 set; trigger on execution timestamp + recycle bin gap." />
          <Heur title="Audit Log Clearing" body="EVTX Security channel scanned for EventID 1102. Cross-validated with surrounding timestamp continuity to rule out legitimate rotation." />
          <Heur title="Timestomping" body="$MFT and $STANDARD_INFORMATION timestamps diffed per file. Divergence ≥ 1s on creation/modification flagged." />
          <Heur title="VSS Shadow Deletion" body="Command-line history and Security EventID 524 inspected for 'vssadmin delete shadows /all' patterns." />
        </ul>
      </Panel>
    </div>
  );
}

function Banner({ level, count, label }: { level: "critical" | "high" | "info"; count: number; label: string }) {
  const map = {
    critical: { c: "text-destructive", b: "border-destructive/40", bg: "bg-destructive/10", glow: "glow-critical" },
    high: { c: "text-[oklch(0.80_0.17_75)]", b: "border-[oklch(0.80_0.17_75_/_0.4)]", bg: "bg-[oklch(0.80_0.17_75_/_0.1)]", glow: "" },
    info: { c: "text-accent", b: "border-accent/40", bg: "bg-accent/10", glow: "" },
  }[level];
  return (
    <div className={`rounded-md border p-5 ${map.b} ${map.bg} ${map.glow}`}>
      <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`mt-2 font-mono text-4xl font-bold ${map.c}`}>{count}</div>
    </div>
  );
}

function SeverityTag({ sev }: { sev: Severity }) {
  const map: Record<Severity, { c: string; bg: string }> = {
    critical: { c: "oklch(0.64 0.24 25)",  bg: "oklch(0.64 0.24 25 / 0.18)" },
    high:     { c: "oklch(0.80 0.17 75)",  bg: "oklch(0.80 0.17 75 / 0.18)" },
    medium:   { c: "oklch(0.78 0.14 210)", bg: "oklch(0.78 0.14 210 / 0.18)" },
    low:      { c: "oklch(0.62 0.018 220)", bg: "oklch(0.62 0.018 220 / 0.18)" },
    info:     { c: "oklch(0.62 0.018 220)", bg: "oklch(0.62 0.018 220 / 0.18)" },
  };
  return <span className="rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase" style={{ color: map[sev].c, background: map[sev].bg }}>{sev}</span>;
}

function Heur({ title, body }: { title: string; body: string }) {
  return (
    <li className="rounded border border-border/60 bg-background/40 p-3">
      <div className="text-primary">{title}</div>
      <div className="mt-1 text-muted-foreground">{body}</div>
    </li>
  );
}
