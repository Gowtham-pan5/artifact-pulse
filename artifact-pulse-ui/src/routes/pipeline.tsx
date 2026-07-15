import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState, useCallback } from "react";
import { toast } from "sonner";
import {
  HardDrive, ScrollText, Cpu, ShieldAlert, Network, Brain, FileLock,
  Play, RotateCcw, ChevronRight, CheckCircle2, Circle, Loader2, XCircle,
} from "lucide-react";
import { PageHeader, Panel } from "./index";
import { pipelineSteps, type PipelineStatus, caseInfo } from "../lib/mockData";
import { api } from "../lib/api";

export const Route = createFileRoute("/pipeline")({
  head: () => ({ meta: [{ title: "Pipeline Runner — Artifact-Pulse" }] }),
  component: PipelinePage,
});

const ICONS = { HardDrive, ScrollText, Cpu, ShieldAlert, Network, Brain, FileLock };

// Map Flask stage names → pipeline step indices
const STAGE_TO_INDEX: Record<string, number> = {
  filesystem: 0,
  eventlogs: 1,
  process: 2,
  antiforensic: 3,
  correlation: 4,
  ml_train: 5, ml_predict: 5, ml_explain: 5,
  seal: 6,
  completed: 6,
};

function PipelinePage() {
  const [statuses, setStatuses] = useState<PipelineStatus[]>(pipelineSteps.map(() => "pending"));
  const [activeLogs, setActiveLogs] = useState<Record<number, number>>({});
  const [running, setRunning] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(0);
  const [liveProgress, setLiveProgress] = useState(0);
  const [liveMessage, setLiveMessage] = useState("");
  const pollerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  function reset() {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    if (pollerRef.current) clearInterval(pollerRef.current);
    setStatuses(pipelineSteps.map(() => "pending"));
    setActiveLogs({});
    setRunning(false);
    setLiveProgress(0);
    setLiveMessage("");
  }

  const pollStatus = useCallback(async () => {
    try {
      const data = await api.extractionStatus();
      setLiveProgress(data.progress || 0);
      setLiveMessage(data.message || "");

      // Update step statuses based on stage
      const idx = STAGE_TO_INDEX[data.stage] ?? -1;
      if (idx >= 0) {
        setStatuses(prev => {
          const next = [...prev];
          // Mark all steps before current as done
          for (let i = 0; i < idx; i++) next[i] = "done";
          // Mark current step as running (or done if completed)
          next[idx] = data.stage === "completed" ? "done" : "running";
          return next;
        });
        setExpanded(idx);
        // Simulate log progress for current step
        const step = pipelineSteps[idx];
        if (step) {
          setActiveLogs(prev => ({
            ...prev,
            [idx]: Math.min((prev[idx] || 0) + 1, step.logs.length),
          }));
        }
      }

      if (!data.running && (data.progress || 0) >= 100) {
        if (pollerRef.current) clearInterval(pollerRef.current);
        setRunning(false);
        // Mark all steps as done
        setStatuses(pipelineSteps.map(() => "done"));
        setActiveLogs(Object.fromEntries(pipelineSteps.map((s, i) => [i, s.logs.length])));
        toast.success("Pipeline complete", { description: "Evidence sealed · PDF ready" });
      }
      if (data.error) {
        if (pollerRef.current) clearInterval(pollerRef.current);
        setRunning(false);
        toast.error("Pipeline error", { description: data.error });
      }
    } catch {
      // backend offline — keep UI running silently
    }
  }, []);

  async function run() {
    reset();
    setRunning(true);
    try {
      await api.startExtraction();
      toast.success("Pipeline started", { description: "Flask backend is processing your endpoint" });
      pollerRef.current = setInterval(pollStatus, 2000);
    } catch {
      // Fallback: demo mode with simulated timers if backend unavailable
      toast.info("Demo mode", { description: "Backend offline — running simulation" });
      let delay = 200;
      pipelineSteps.forEach((step, i) => {
        timers.current.push(setTimeout(() => {
          setStatuses(prev => { const n = [...prev]; n[i] = "running"; return n; });
          setExpanded(i);
          step.logs.forEach((_, li) => {
            timers.current.push(setTimeout(() => {
              setActiveLogs(prev => ({ ...prev, [i]: li + 1 }));
            }, li * 240));
          });
        }, delay));
        delay += step.logs.length * 240 + 400;
        timers.current.push(setTimeout(() => {
          setStatuses(prev => { const n = [...prev]; n[i] = "done"; return n; });
        }, delay));
        delay += 250;
      });
      timers.current.push(setTimeout(() => {
        setRunning(false);
        toast.success("Demo complete", { description: "Simulation finished" });
      }, delay + 200));
    }
  }

  useEffect(() => () => {
    timers.current.forEach(clearTimeout);
    if (pollerRef.current) clearInterval(pollerRef.current);
  }, []);

  const completed = statuses.filter(s => s === "done").length;
  const totalPct = Math.round((completed / pipelineSteps.length) * 100);

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
                style={{ width: `${liveProgress || totalPct}%` }}
              />
            </div>
            {liveMessage && (
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">{liveMessage}</p>
            )}
          </div>
          <div className="font-mono text-2xl font-bold text-primary">{liveProgress || totalPct}%</div>
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
          const logCount = activeLogs[i] ?? (status === "done" ? step.logs.length : 0);
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
