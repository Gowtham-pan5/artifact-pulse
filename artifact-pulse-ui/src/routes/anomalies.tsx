import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip, ZAxis, Cell,
} from "recharts";
import { Brain, Flame } from "lucide-react";
import { PageHeader, Panel } from "./index";
import { anomalyPoints, type AnomalyPoint } from "../lib/mockData";

export const Route = createFileRoute("/anomalies")({
  head: () => ({ meta: [{ title: "Anomaly Detection — Artifact-Pulse" }] }),
  component: AnomaliesPage,
});

const CLUSTER_COLORS = [
  "oklch(0.82 0.18 155)",
  "oklch(0.78 0.14 210)",
  "oklch(0.68 0.18 295)",
  "oklch(0.80 0.17 75)",
  "oklch(0.64 0.24 25)",
];

const tt = {
  background: "oklch(0.19 0.014 240)",
  border: "1px solid oklch(0.28 0.016 240)",
  borderRadius: 4,
  fontFamily: "JetBrains Mono",
  fontSize: 11,
};

function AnomaliesPage() {
  const [selected, setSelected] = useState<AnomalyPoint | null>(anomalyPoints[8]);
  const ranked = [...anomalyPoints].sort((a, b) => b.score - a.score);

  return (
    <div className="mx-auto max-w-[1500px] space-y-6">
      <PageHeader title="Anomaly Detection" subtitle="Isolation Forest · KMeans (k=5) · TF-IDF · weighted ensemble" />

      <div className="grid gap-4 lg:grid-cols-4">
        <KpiTile label="Top score" value={ranked[0].score.toFixed(2)} tone="critical" icon={Flame} />
        <KpiTile label="Anomalies surfaced" value={String(anomalyPoints.length)} tone="primary" icon={Brain} />
        <KpiTile label="Clusters" value="5" tone="accent" icon={Brain} />
        <KpiTile label="False-positive rate" value="< 5%" tone="primary" icon={Brain} sub="contamination=0.05" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel className="lg:col-span-2" title="Anomaly Scatter" subtitle="x: minutes from t0 · y: ensemble score · color: kmeans cluster">
          <div className="h-[420px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 20, right: 20, left: 0, bottom: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="oklch(0.28 0.016 240)" />
                <XAxis type="number" dataKey="timeMin" name="time" unit="m"
                  stroke="oklch(0.62 0.018 220)" fontSize={11} fontFamily="JetBrains Mono" domain={[0, "dataMax + 1"]} />
                <YAxis type="number" dataKey="score" name="score"
                  stroke="oklch(0.62 0.018 220)" fontSize={11} fontFamily="JetBrains Mono" domain={[0.5, 1]} />
                <ZAxis range={[80, 220]} />
                <Tooltip cursor={{ strokeDasharray: "3 3", stroke: "oklch(0.82 0.18 155)" }} contentStyle={tt} />
                <Scatter
                  data={anomalyPoints}
                  onClick={(d: any) => setSelected(d as AnomalyPoint)}
                >
                  {anomalyPoints.map((p, i) => (
                    <Cell
                      key={i}
                      fill={CLUSTER_COLORS[p.cluster]}
                      stroke={selected?.id === p.id ? "oklch(0.93 0.012 200)" : "transparent"}
                      strokeWidth={2}
                    />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex flex-wrap gap-3 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {CLUSTER_COLORS.map((c, i) => (
              <div key={i} className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ background: c }} />
                cluster_{i}
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="Anomaly Detail" subtitle={selected ? selected.id : "select a point"}>
          {selected ? (
            <div className="space-y-3 font-mono text-xs">
              <Row k="artifact_ref" v={selected.artifactId} highlight />
              <Row k="ensemble_score" v={selected.score.toFixed(3)} accent />
              <Row k="kmeans_cluster" v={`cluster_${selected.cluster}`} />
              <Row k="t_offset" v={`${selected.timeMin.toFixed(1)} min from t0`} />
              <div>
                <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">// why flagged</div>
                <div className="flex flex-wrap gap-1.5">
                  {selected.reasons.map(r => (
                    <span key={r} className="rounded border border-accent/40 bg-accent/10 px-2 py-0.5 text-accent">{r}</span>
                  ))}
                </div>
              </div>
              <div className="rounded border border-border/60 bg-background/60 p-3">
                <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">explainability</div>
                <div className="text-foreground">
                  Isolation depth: <span className="text-primary">{(11 - selected.score * 8).toFixed(2)}</span>.
                  TF-IDF keyword weight: <span className="text-primary">{(selected.score * 0.93).toFixed(2)}</span>.
                  KMeans distance to centroid above 1.5σ.
                </div>
              </div>
            </div>
          ) : (
            <div className="py-8 text-center font-mono text-xs text-muted-foreground">// click a scatter point to inspect</div>
          )}
        </Panel>
      </div>

      <Panel title="Ranked Anomalies" subtitle="sorted by ensemble score · descending">
        <div className="overflow-x-auto">
          <table className="w-full font-mono text-xs">
            <thead>
              <tr className="border-b border-border/60 text-left text-muted-foreground">
                <th className="px-2 py-3 font-medium">rank</th>
                <th className="px-2 py-3 font-medium">id</th>
                <th className="px-2 py-3 font-medium">artifact</th>
                <th className="px-2 py-3 font-medium">cluster</th>
                <th className="px-2 py-3 font-medium">score</th>
                <th className="px-2 py-3 font-medium">reasons</th>
              </tr>
            </thead>
            <tbody>
              {ranked.map((p, i) => (
                <tr
                  key={p.id}
                  onClick={() => setSelected(p)}
                  className={`cursor-pointer border-b border-border/30 hover:bg-primary/5 ${selected?.id === p.id ? "bg-primary/10" : ""}`}
                >
                  <td className="px-2 py-2.5 text-muted-foreground">#{i + 1}</td>
                  <td className="px-2 py-2.5 text-primary">{p.id}</td>
                  <td className="px-2 py-2.5 text-foreground">{p.artifactId}</td>
                  <td className="px-2 py-2.5"><span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: CLUSTER_COLORS[p.cluster] + "22", color: CLUSTER_COLORS[p.cluster] }}>cluster_{p.cluster}</span></td>
                  <td className="px-2 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-muted">
                        <div className="h-full bg-destructive" style={{ width: `${p.score * 100}%` }} />
                      </div>
                      <span className="text-destructive">{p.score.toFixed(2)}</span>
                    </div>
                  </td>
                  <td className="px-2 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {p.reasons.map(r => (
                        <span key={r} className="rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-[10px] text-muted-foreground">{r}</span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function KpiTile({ label, value, sub, tone, icon: Icon }: { label: string; value: string; sub?: string; tone: "primary" | "accent" | "critical"; icon: typeof Brain }) {
  const map = {
    primary: "border-primary/30 text-primary",
    accent: "border-accent/30 text-accent",
    critical: "border-destructive/40 text-destructive",
  };
  return (
    <div className={`rounded-md border bg-card/40 p-4 ${map[tone]}`}>
      <div className="flex items-center justify-between">
        <Icon className="h-4 w-4" />
        {sub && <span className="font-mono text-[9px] uppercase tracking-wider text-muted-foreground">{sub}</span>}
      </div>
      <div className="mt-3 font-mono text-2xl font-bold">{value}</div>
      <div className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
    </div>
  );
}

function Row({ k, v, highlight, accent }: { k: string; v: string; highlight?: boolean; accent?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/40 pb-2 last:border-0">
      <span className="text-muted-foreground">{k}</span>
      <span className={highlight ? "text-primary" : accent ? "text-accent" : "text-foreground"}>{v}</span>
    </div>
  );
}
