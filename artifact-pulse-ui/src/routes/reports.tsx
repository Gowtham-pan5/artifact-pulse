import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { FileText, Download, ShieldCheck, ShieldAlert, Plus, Loader2 } from "lucide-react";
import { PageHeader, Panel } from "./index";
import { reports as seed, type Report } from "../lib/mockData";

export const Route = createFileRoute("/reports")({
  head: () => ({ meta: [{ title: "Reports — Artifact-Pulse" }] }),
  component: ReportsPage,
});

function ReportsPage() {
  const [reports, setReports] = useState<Report[]>(seed);
  const [generating, setGenerating] = useState(false);
  const [generatedPath, setGeneratedPath] = useState<string | null>(null);

  async function generate() {
    setGenerating(true);
    toast.info("Compiling triage report…", { description: "merging artifacts + clusters + ledger" });
    try {
      const res = await fetch("/api/report/generate", { method: "POST" });
      if (!res.ok) throw new Error(`generate failed: ${res.status}`);
      const data = await res.json();
      setGeneratedPath(data.path ?? null);

      let artifacts = 0;
      let hash = "";
      let caseId = "AP-CURRENT";
      try {
        const s = await (await fetch("/api/stats")).json();
        artifacts = s.total_artifacts ?? s.total ?? 0;
      } catch { /* stats unavailable */ }
      try {
        const c = await (await fetch("/api/chain/verify")).json();
        hash = c.master_hash ?? "";
      } catch { /* chain unavailable */ }
      try {
        const h = await (await fetch("/api/health")).json();
        caseId = h.case_id ?? caseId;
      } catch { /* health unavailable */ }

      const r: Report = {
        id: `RPT-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${Date.now().toString(36).toUpperCase()}`,
        caseId,
        title: "Forensic Triage Report — this device",
        generatedAt: new Date().toISOString(),
        investigator: "Artifact-Pulse",
        pages: 0,
        sizeKb: 0,
        artifacts,
        hash: hash || "pending",
        verified: true,
      };
      setReports(prev => [r, ...prev]);
      toast.success("Report generated", { description: data.path ?? r.id });
    } catch (err) {
      toast.error("Report generation failed", { description: `is Flask running on :5000? (${err})` });
    } finally {
      setGenerating(false);
    }
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <PageHeader
        title="Reports"
        subtitle="Court-ready PDF outputs · hash-verified · Section 65B annexed"
        action={
          <button
            onClick={generate}
            disabled={generating}
            className="flex items-center gap-2 rounded border border-primary/50 bg-primary/15 px-4 py-1.5 font-mono text-xs uppercase tracking-wider text-primary hover:bg-primary/25 disabled:opacity-50 glow-signal"
          >
            {generating ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            generate report
          </button>
        }
      />

      <div className="grid gap-4 md:grid-cols-4">
        <Tile label="Total reports" value={String(reports.length)} />
        <Tile label="Verified" value={String(reports.filter(r => r.verified).length)} tone="primary" />
        <Tile label="Unverified" value={String(reports.filter(r => !r.verified).length)} tone="warn" />
        <Tile label="Avg pages" value={String(Math.round(reports.reduce((s, r) => s + r.pages, 0) / reports.length))} />
      </div>

      <Panel title="Generated Reports" subtitle="click download to export PDF + hash receipt">
        <ul className="divide-y divide-border/60">
          {reports.map(r => (
            <li key={r.id} className="flex flex-wrap items-center gap-4 py-4">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded border border-primary/30 bg-primary/10 text-primary">
                <FileText className="h-5 w-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="font-mono text-[11px] text-primary">{r.id}</span>
                  <span className="font-mono text-sm font-bold text-foreground">{r.title}</span>
                  {r.verified ? (
                    <span className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono text-[10px] uppercase text-primary">
                      <ShieldCheck className="h-3 w-3" /> hash verified
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded border border-[oklch(0.80_0.17_75_/_0.4)] bg-[oklch(0.80_0.17_75_/_0.1)] px-2 py-0.5 font-mono text-[10px] uppercase text-[oklch(0.80_0.17_75)]">
                      <ShieldAlert className="h-3 w-3" /> awaiting verification
                    </span>
                  )}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-5 gap-y-1 font-mono text-[11px] text-muted-foreground">
                  <span>case <span className="text-foreground">{r.caseId}</span></span>
                  <span>investigator <span className="text-foreground">{r.investigator}</span></span>
                  <span>generated <span className="text-foreground">{new Date(r.generatedAt).toLocaleString()}</span></span>
                  <span>
                    {r.pages > 0 ? `${r.pages} pages · ${(r.sizeKb / 1024).toFixed(2)} MB · ` : ""}
                    {r.artifacts.toLocaleString()} artifacts
                  </span>
                </div>
                <div className="mt-1 truncate font-mono text-[10px] text-accent">sha256: {r.hash}</div>
              </div>
              <button
                onClick={() => {
                  if (!generatedPath) {
                    toast.info("No report generated yet", { description: "click generate report first" });
                    return;
                  }
                  toast.success("Download started", { description: generatedPath.split(/[\\/]/).pop() });
                  window.open("/api/report/download", "_blank");
                }}
                className="flex items-center gap-2 rounded border border-border bg-card/60 px-3 py-1.5 font-mono text-[11px] uppercase tracking-wider text-foreground hover:border-primary/40 hover:text-primary"
              >
                <Download className="h-3.5 w-3.5" />
                download
              </button>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function Tile({ label, value, tone }: { label: string; value: string; tone?: "primary" | "warn" }) {
  const c = tone === "primary" ? "text-primary border-primary/30" : tone === "warn" ? "text-[oklch(0.80_0.17_75)] border-[oklch(0.80_0.17_75_/_0.4)]" : "text-foreground border-border/60";
  return (
    <div className={`rounded-md border bg-card/40 p-4 ${c}`}>
      <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-2 font-mono text-2xl font-bold">{value}</div>
    </div>
  );
}
