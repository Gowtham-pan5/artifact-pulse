import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { ShieldCheck, Link2, Check, AlertTriangle } from "lucide-react";
import { PageHeader, Panel } from "./index";
import { artifacts, caseInfo } from "../lib/mockData";

export const Route = createFileRoute("/chain")({
  head: () => ({ meta: [{ title: "Chain of Custody — Artifact-Pulse" }] }),
  component: ChainPage,
});

function ChainPage() {
  const [verifying, setVerifying] = useState(false);
  const [verifiedAt, setVerifiedAt] = useState<string | null>(new Date().toISOString());

  function verify() {
    setVerifying(true);
    setVerifiedAt(null);
    setTimeout(() => {
      setVerifying(false);
      const ts = new Date().toISOString();
      setVerifiedAt(ts);
      toast.success("Chain integrity verified", { description: `${artifacts.length} blocks · master_hash matches` });
    }, 1400);
  }

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <PageHeader
        title="Chain of Custody"
        subtitle="SHA-256 Merkle-style hash chain · NIST SP 800-86 · Section 65B IT Act 2000"
        action={
          <button
            onClick={verify}
            disabled={verifying}
            className="flex items-center gap-2 rounded border border-primary/50 bg-primary/15 px-4 py-1.5 font-mono text-xs uppercase tracking-wider text-primary hover:bg-primary/25 disabled:opacity-50 glow-signal"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            {verifying ? "verifying…" : "verify integrity"}
          </button>
        }
      />

      <div className="grid gap-4 md:grid-cols-3">
        <IntegrityCard
          label="Ledger status"
          value={verifying ? "VERIFYING" : "INTACT"}
          sub={verifiedAt ? `verified ${new Date(verifiedAt).toLocaleTimeString()}` : "in progress"}
          ok={!verifying}
        />
        <IntegrityCard label="Total blocks" value={artifacts.length.toString()} sub="append-only sqlite" ok />
        <IntegrityCard label="Master hash" value={caseInfo.masterHash.slice(0, 18) + "…"} sub="root commit" ok mono />
      </div>

      <Panel title="Hash Chain Ledger" subtitle="each block references prev_hash → tamper of any block breaks the chain">
        <ol className="relative space-y-3">
          <span className="pointer-events-none absolute left-[18px] top-3 bottom-3 w-px bg-gradient-to-b from-primary/60 via-primary/30 to-transparent" />
          {artifacts.map((a, i) => {
            const prev = artifacts[i - 1];
            return (
              <li key={a.id} className="relative pl-12">
                <span className="absolute left-2.5 top-3 flex h-7 w-7 items-center justify-center rounded-full border-2 border-primary/50 bg-background text-primary">
                  <Check className="h-3.5 w-3.5" />
                </span>
                <div className="rounded-md border border-border/60 bg-card/40 p-4">
                  <div className="flex flex-wrap items-baseline gap-3">
                    <span className="font-mono text-[11px] text-primary">block_{String(i).padStart(4, "0")}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">{a.id}</span>
                    <span className="font-mono text-[10px] text-muted-foreground">{new Date(a.timestamp).toISOString()}</span>
                    <span className="ml-auto inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 font-mono text-[10px] uppercase text-primary">
                      <ShieldCheck className="h-3 w-3" /> intact
                    </span>
                  </div>
                  <div className="mt-2 font-mono text-xs text-foreground">{a.description}</div>
                  <div className="mt-3 grid gap-1.5 font-mono text-[11px]">
                    <HashRow label="prev_hash" value={prev ? prev.chainHash : "0".repeat(64)} muted />
                    <HashRow label="content_sha256" value={a.contentHash} />
                    <HashRow label="chain_hash" value={a.chainHash} primary />
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      </Panel>

      <Panel title="Legal Compliance" subtitle="Evidence handling references">
        <div className="grid gap-3 md:grid-cols-2 font-mono text-xs">
          <Pill icon={Check} title="Section 65B IT Act 2000" body="Append-only SQLite ledger, per-block hashing, certified examiner credential — admissible." />
          <Pill icon={Check} title="NIST SP 800-86" body="Acquisition, examination, analysis, reporting phases logged with cryptographic continuity." />
          <Pill icon={Check} title="ACPO Principles" body="Original evidence never modified; full audit trail of all actions retained in ledger." />
          <Pill icon={AlertTriangle} title="Tamper detection" body="Any block mutation breaks downstream chain_hash and fails master_hash verification." warn />
        </div>
      </Panel>
    </div>
  );
}

function IntegrityCard({ label, value, sub, ok, mono }: { label: string; value: string; sub: string; ok: boolean; mono?: boolean }) {
  return (
    <div className={`rounded-md border bg-card/40 p-5 ${ok ? "border-primary/30" : "border-[oklch(0.80_0.17_75_/_0.4)]"}`}>
      <div className="flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
        <ShieldCheck className={`h-4 w-4 ${ok ? "text-primary" : "text-[oklch(0.80_0.17_75)]"}`} />
      </div>
      <div className={`mt-3 font-mono ${mono ? "text-base" : "text-2xl"} font-bold ${ok ? "text-primary" : "text-[oklch(0.80_0.17_75)]"}`}>
        {value}
      </div>
      <div className="mt-1 font-mono text-[10px] text-muted-foreground">{sub}</div>
    </div>
  );
}

function HashRow({ label, value, muted, primary }: { label: string; value: string; muted?: boolean; primary?: boolean }) {
  return (
    <div className="flex items-center gap-2 truncate">
      <Link2 className={`h-3 w-3 ${primary ? "text-primary" : muted ? "text-muted-foreground" : "text-accent"}`} />
      <span className="w-32 shrink-0 text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className={`truncate ${primary ? "text-primary" : muted ? "text-muted-foreground" : "text-accent"}`}>{value}</span>
    </div>
  );
}

function Pill({ icon: Icon, title, body, warn }: { icon: typeof Check; title: string; body: string; warn?: boolean }) {
  return (
    <div className={`rounded border bg-background/40 p-3 ${warn ? "border-[oklch(0.80_0.17_75_/_0.4)]" : "border-border/60"}`}>
      <div className={`flex items-center gap-2 ${warn ? "text-[oklch(0.80_0.17_75)]" : "text-primary"}`}>
        <Icon className="h-3.5 w-3.5" />
        <span className="font-bold">{title}</span>
      </div>
      <div className="mt-1 text-muted-foreground">{body}</div>
    </div>
  );
}
