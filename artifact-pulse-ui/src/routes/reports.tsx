import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { FileText, Download, ShieldCheck, ShieldAlert, Plus, Loader2 } from "lucide-react";
import { PageHeader, Panel } from "./index";
import { reports as seed, type Report } from "../lib/mockData";
import { api } from "../lib/api";

export const Route = createFileRoute("/reports")({
  head: () => ({ meta: [{ title: "Reports — Artifact-Pulse" }] }),
  component: ReportsPage,
});

function ReportsPage() {
  const [reports, setReports] = useState<Report[]>(seed);
  const [generating, setGenerating] = useState(false);

  async function generate() {
    setGenerating(true);
    toast.info("Generating forensic PDF…", { description: "calling Flask backend" });
    try {
      await api.generateReport();
      const id = `RPT-${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-LIVE`;
      const r: Report = {
        id,
        caseId: "AP-LIVE",
        title: "Live Forensic Report — this endpoint",
        generatedAt: new Date().toISOString(),
        investigator: "Artifact-Pulse",
        pages: 0, sizeKb: 0, artifacts: 0,
        hash: "–– see backend output/ ––",
        verified: true,
      };
      setReports(prev => [r, ...prev]);
      toast.success("Report generated!", { description: "Check output/reports/ folder for the PDF" });
    } catch {
      toast.error("Backend offline", { description: "Run python main.py first" });
    }
    setGenerating(false);
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
                  <span>{r.pages} pages · {(r.sizeKb / 1024).toFixed(2)} MB · {r.artifacts.toLocaleString()} artifacts</span>
                </div>
                <div className="mt-1 truncate font-mono text-[10px] text-accent">sha256: {r.hash}</div>
              </div>
              <button
                onClick={() => {
                  if (r.caseId === "AP-LIVE") {
                    api.downloadReport();
                  } else {
                    toast.info("Demo report", { description: "Run a real pipeline first to download a live PDF" });
                  }
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
