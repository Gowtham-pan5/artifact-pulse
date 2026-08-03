import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import {
  HardDrive, ScrollText, Cpu, ShieldAlert, Network, Brain, FileLock,
  Play, RotateCcw, ChevronRight, CheckCircle2, Circle, Loader2, XCircle,
} from "lucide-react";
import { PageHeader, Panel } from "./index";
import { pipelineSteps, type PipelineStatus, caseInfo } from "../lib/mockData";

export const Route = createFileRoute("/pipeline")({
  head: () => ({ meta: [{ title: "Pipeline Runner — Artifact-Pulse" }] }),
  component: PipelinePage,
});

const ICONS = { HardDrive, ScrollText, Cpu, ShieldAlert, Network, Brain, FileLock };

const STAGE_TO_STEP: Record<string, number> = {
  starting: 0,
  filesystem: 0,
  eventlogs: 1,
  process: 2,
  antiforensic: 3,
  correlation: 4,
  ml_train: 5,
  ml_predict: 5,
  ml_explain: 5,
  seal: 6,
};

function PipelinePage() {
  const [statuses, setStatuses] = useState<PipelineStatus[]>(pipelineSteps.map(() => "pending"));
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stageMessage, setStageMessage] = useState("");
  const [expanded, setExpanded] = useState<number | null>(0);
  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function stopPolling() {
    if (pollTimer.current) {
      clearTimeout(pollTimer.current);
      pollTimer.current = null;
    }
  }

  function reset() {
    stopPolling();
    setStatuses(pipelineSteps.map(() => "pending"));
    setProgress(0);
    setStageMessage("");
    setRunning(false);
  }

  async function poll() {
    try {
      const res = await fetch("/api/extraction/status");
      if (!res.ok) throw new Error(`status ${res.status}`);
      const st = await res.json();
      const activeIdx = STAGE_TO_STEP[st.stage] ?? -1;
      setProgress(st.progress ?? 0);
      setStageMessage(st.message ?? "");

      if (st.stage === "completed") {
        setStatuses(prev => prev.map(() => "done"));
        setRunning(false);
        toast.success("Pipeline complete", { description: st.message ?? "Evidence sealed" });
        return;
      }
      if (st.stage === "error" || st.error) {
        setStatuses(prev => prev.map((s, i) => (i <= activeIdx ? "failed" : s)));
        setRunning(false);
        toast.error("Pipeline failed", { description: st.error ?? st.message });
        return;
      }
      if (activeIdx >= 0) {
        setStatuses(prev =>
          prev.map((s, i) =>
            i < activeIdx ? "done" : i === activeIdx ? "running" : "pending"
          )
        );
        setExpanded(activeIdx);
      }
      if (st.running) pollTimer.current = setTimeout(poll, 2500);
    } catch (err) {
      setRunning(false);
      toast.error("Lost connection to backend", { description: String(err) });
    }
  }

  function run() {
    reset();
    setRunning(true);
    toast.success("Pipeline started", { description: `target: ${caseInfo.hostName}` });
    fetch("/api/extraction/start", { method: "POST" })
      .then(async res => {
        if (res.status === 409) {
          toast.info("Pipeline already running", { description: "polling existing run" });
          poll();
          return;
        }
        if (!res.ok) throw new Error(`start failed: ${res.status}`);
        poll();
      })
      .catch(err => {
        setRunning(false);
        setStatuses(prev => prev.map(() => "failed"));
        toast.error("Backend unreachable", { description: `is Flask running on :5000? (${err})` });
      });
  }

  useEffect(() => () => stopPolling(), []);

  const completed = statuses.filter(s => s === "done").length;
  const totalPct = running ? progress : Math.round((completed / pipelineSteps.length) * 100);

  return (
    <div className="mx-auto max-w-[1300px] space-y-6">
      <PageHeader
        title="Pipeline Runner"
        subtitle="Sequential 7-stage extraction → correlation → seal"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={reset}
              disabled={running}
              className="flex items-center gap-2 rounded border border-border bg-card/40 px-3 py-1.5 font-mono text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground disabled:opacity-40"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              reset
            </button>
            <button
              onClick={run}
              disabled={running}
              className="flex items-center gap-2 rounded border border-primary/50 bg-primary/15 px-4 py-1.5 font-mono text-xs uppercase tracking-wider text-primary hover:bg-primary/25 disabled:opacity-40 glow-signal"
            >
              {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {running ? "running…" : "run pipeline"}
            </button>
          </div>
        }
      />

      <Panel title="Overall Progress" subtitle={`target endpoint: ${caseInfo.hostName} · 7 stages`}>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-gradient-to-r from-primary to-accent transition-all duration-300"
                style={{ width: `${totalPct}%` }}
              />
            </div>
          </div>
          <div className="font-mono text-2xl font-bold text-primary">{totalPct}%</div>
          <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {completed} / {pipelineSteps.length} stages
          </div>
        </div>
      </Panel>

      <div className="space-y-3">
        {pipelineSteps.map((step, i) => {
          const status = statuses[i];
          const Icon = (ICONS as any)[step.icon] ?? Circle;
          const isOpen = expanded === i;
          const logCount = status === "done" ? step.logs.length : status === "running" ? step.logs.length - 1 : 0;
          return (
            <div
              key={step.id}
              className={`overflow-hidden rounded-md border bg-card/30 transition-colors ${
                status === "running" ? "border-primary/50 glow-signal"
                : status === "done" ? "border-primary/25"
                : status === "failed" ? "border-destructive/40"
                : "border-border/60"
              }`}
            >
              <button
                onClick={() => setExpanded(isOpen ? null : i)}
                className="flex w-full items-center gap-4 px-5 py-4 text-left hover:bg-card/50"
              >
                <StatusIcon status={status} />
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded border border-border bg-background/60">
                  <Icon className="h-4 w-4 text-primary" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span className="font-mono text-[10px] text-muted-foreground">stage_{String(step.id).padStart(2, "0")}</span>
                    <span className="font-mono text-sm font-bold text-foreground">{step.name}</span>
                  </div>
                  <div className="font-mono text-[11px] text-muted-foreground">{step.description}</div>
                </div>
                <div className="hidden font-mono text-[11px] text-accent md:block">{step.module}</div>
                <StatusPill status={status} />
                <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${isOpen ? "rotate-90" : ""}`} />
              </button>

              {isOpen && (
                <div className="border-t border-border/60 bg-background/60 px-5 py-3">
                  <div className="font-mono text-[11px]">
                    {step.logs.slice(0, logCount).map((log, li) => (
                      <div key={li} className="terminal-feed-line flex gap-2 py-0.5">
                        <span className="shrink-0 text-muted-foreground">[{String(li).padStart(2, "0")}]</span>
                        <span className={log.startsWith("[!]") ? "text-destructive" : log.startsWith("[✓]") ? "text-primary" : "text-foreground"}>
                          {log}
                        </span>
                      </div>
                    ))}
                    {status === "running" && stageMessage && (
                      <div className="terminal-feed-line flex gap-2 py-0.5">
                        <span className="text-primary">[→]</span>
                        <span className="text-foreground">{stageMessage}</span>
                      </div>
                    )}
                    {status === "running" && <div className="text-primary blink-caret py-0.5" />}
                    {status === "pending" && <div className="py-2 text-muted-foreground">// awaiting upstream stage…</div>}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StatusIcon({ status }: { status: PipelineStatus }) {
  if (status === "done") return <CheckCircle2 className="h-5 w-5 text-primary" />;
  if (status === "running") return <Loader2 className="h-5 w-5 animate-spin text-primary" />;
  if (status === "failed") return <XCircle className="h-5 w-5 text-destructive" />;
  return <Circle className="h-5 w-5 text-muted-foreground" />;
}

function StatusPill({ status }: { status: PipelineStatus }) {
  const map = {
    pending: { c: "text-muted-foreground", bg: "bg-muted/40", label: "PENDING" },
    running: { c: "text-primary", bg: "bg-primary/15", label: "RUNNING" },
    done: { c: "text-primary", bg: "bg-primary/20", label: "DONE" },
    failed: { c: "text-destructive", bg: "bg-destructive/20", label: "FAILED" },
  }[status];
  return (
    <span className={`hidden rounded border border-border px-2 py-0.5 font-mono text-[9px] uppercase tracking-wider md:inline-block ${map.c} ${map.bg}`}>
      {map.label}
    </span>
  );
}
