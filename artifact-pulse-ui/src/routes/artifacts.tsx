import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Search, ArrowUpDown, X, Copy } from "lucide-react";
import { toast } from "sonner";
import { PageHeader, Panel } from "./index";
import { artifacts as mockArtifacts, type Layer, type Severity } from "../lib/mockData";
import { api, type Artifact as ApiArtifact } from "../lib/api";

export const Route = createFileRoute("/artifacts")({
  head: () => ({ meta: [{ title: "Artifacts Explorer — Artifact-Pulse" }] }),
  component: ArtifactsPage,
});

// Map backend artifact to a consistent display shape
type DisplayArtifact = {
  id: string;
  timestamp: string;
  layer: string;
  source: string;
  description: string;
  severity: string;
  contentHash: string;
  chainHash: string;
  riskWeight: number;
};

function backendToDisplay(a: ApiArtifact): DisplayArtifact {
  const risk = a.risk_weight ?? 0;
  const sev = risk >= 0.7 ? "high" : risk >= 0.4 ? "medium" : "low";
  return {
    id: `AF-${String(a.artifact_id).padStart(4, "0")}`,
    timestamp: a.event_time || "",
    layer: a.source_layer || "filesystem",
    source: a.source_path || "",
    description: `${a.artifact_type || "unknown"} — ${a.source_path || ""}`,
    severity: sev,
    contentHash: a.content_hash || "",
    chainHash: a.chain_hash || "",
    riskWeight: risk,
  };
}

const LAYERS: ("all" | string)[] = ["all", "filesystem", "system_events", "process_snapshot", "registry"];
const SEVS: ("all" | Severity)[] = ["all", "critical", "high", "medium", "low"];

function ArtifactsPage() {
  const [q, setQ] = useState("");
  const [layer, setLayer] = useState<string>("all");
  const [sev, setSev] = useState<string>("all");
  const [sortKey, setSortKey] = useState<keyof DisplayArtifact>("timestamp");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [selected, setSelected] = useState<DisplayArtifact | null>(null);
  const [liveArtifacts, setLiveArtifacts] = useState<DisplayArtifact[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    api.artifacts()
      .then(data => {
        setLiveArtifacts(data.map(backendToDisplay));
        setLoaded(true);
      })
      .catch(() => setLoaded(true));  // silently fall back to mock
  }, []);

  // Use live data if available, otherwise fall back to mock
  const allArtifacts: DisplayArtifact[] = loaded && liveArtifacts.length > 0
    ? liveArtifacts
    : (mockArtifacts as unknown as DisplayArtifact[]);

  const filtered = useMemo(() => {
    const lower = q.toLowerCase();
    return allArtifacts
      .filter(a =>
        (layer === "all" || a.layer === layer)
        && (sev === "all" || a.severity === sev)
        && (lower === "" || a.description.toLowerCase().includes(lower) || a.source.toLowerCase().includes(lower) || a.id.toLowerCase().includes(lower))
      )
      .sort((a, b) => {
        const av = a[sortKey] as unknown, bv = b[sortKey] as unknown;
        if ((av as string) < (bv as string)) return sortDir === "asc" ? -1 : 1;
        if ((av as string) > (bv as string)) return sortDir === "asc" ? 1 : -1;
        return 0;
      });
  }, [q, layer, sev, sortKey, sortDir, allArtifacts]);

  function toggleSort(k: keyof DisplayArtifact) {
    if (sortKey === k) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(k); setSortDir("desc"); }
  }

  return (
    <div className="mx-auto max-w-[1500px] space-y-6">
      <PageHeader title="Artifacts Explorer" subtitle={`${allArtifacts.length} indexed · ${loaded && liveArtifacts.length > 0 ? "live from backend" : "demo data"} · sortable · filterable`} />

      <Panel title="Filters" subtitle={`showing ${filtered.length} of ${artifacts.length}`}>
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[260px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={q}
              onChange={e => setQ(e.target.value)}
              placeholder="search description, source, id…"
              className="w-full rounded border border-border bg-background/60 py-1.5 pl-9 pr-3 font-mono text-xs focus:border-primary/50 focus:outline-none"
            />
          </div>
          <FilterGroup label="layer" options={LAYERS} value={layer} onChange={setLayer} />
          <FilterGroup label="severity" options={SEVS} value={sev} onChange={setSev} />
        </div>
      </Panel>

      <div className={`grid gap-4 ${selected ? "lg:grid-cols-[1fr_380px]" : ""}`}>
        <Panel title="Artifact Index" subtitle="click row for detail">
          <div className="overflow-x-auto">
            <table className="w-full font-mono text-xs">
              <thead>
                <tr className="border-b border-border/60 text-left text-muted-foreground">
                  <Th onClick={() => toggleSort("id")} active={sortKey === "id"}>id</Th>
                  <Th onClick={() => toggleSort("timestamp")} active={sortKey === "timestamp"}>timestamp</Th>
                  <Th onClick={() => toggleSort("layer")} active={sortKey === "layer"}>layer</Th>
                  <th className="px-2 py-3 font-medium">source</th>
                  <th className="px-2 py-3 font-medium">description</th>
                  <Th onClick={() => toggleSort("riskWeight")} active={sortKey === "riskWeight"}>risk</Th>
                  <Th onClick={() => toggleSort("severity")} active={sortKey === "severity"}>sev</Th>
                  <th className="px-2 py-3 font-medium">hash</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(a => (
                  <tr
                    key={a.id}
                    onClick={() => setSelected(a)}
                    className={`cursor-pointer border-b border-border/30 transition-colors hover:bg-primary/5 ${selected?.id === a.id ? "bg-primary/10" : ""}`}
                  >
                    <td className="px-2 py-2.5 text-primary">{a.id}</td>
                    <td className="px-2 py-2.5 text-muted-foreground">{new Date(a.timestamp).toLocaleTimeString()}</td>
                    <td className="px-2 py-2.5"><LayerBadge layer={a.layer} /></td>
                    <td className="px-2 py-2.5 max-w-[140px] truncate text-muted-foreground">{a.source}</td>
                    <td className="px-2 py-2.5 max-w-[360px] truncate text-foreground">{a.description}</td>
                    <td className="px-2 py-2.5 text-accent">{a.riskWeight.toFixed(2)}</td>
                    <td className="px-2 py-2.5"><SeverityBadge sev={a.severity} /></td>
                    <td className="px-2 py-2.5 text-muted-foreground">{a.contentHash.slice(0, 10)}…</td>
                  </tr>
                ))}
                {filtered.length === 0 && (
                  <tr><td colSpan={8} className="py-10 text-center text-muted-foreground">// no artifacts match filters</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        {selected && <DetailPanel artifact={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

function Th({ children, onClick, active }: { children: React.ReactNode; onClick: () => void; active?: boolean }) {
  return (
    <th onClick={onClick} className={`cursor-pointer select-none px-2 py-3 font-medium hover:text-foreground ${active ? "text-primary" : ""}`}>
      <span className="inline-flex items-center gap-1">{children}<ArrowUpDown className="h-3 w-3 opacity-60" /></span>
    </th>
  );
}

function FilterGroup<T extends string>({ label, options, value, onChange }: { label: string; options: readonly T[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="flex items-center gap-1.5 rounded border border-border bg-background/40 p-1">
      <span className="px-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
      {options.map(o => (
        <button
          key={o}
          onClick={() => onChange(o)}
          className={`rounded px-2 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors ${
            value === o ? "bg-primary/20 text-primary" : "text-muted-foreground hover:bg-card/60 hover:text-foreground"
          }`}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

function DetailPanel({ artifact, onClose }: { artifact: Artifact; onClose: () => void }) {
  function copy(s: string) { navigator.clipboard.writeText(s); toast.success("copied to clipboard"); }
  return (
    <Panel
      title={`Artifact ${artifact.id}`}
      subtitle={artifact.source}
      right={<button onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-card/60 hover:text-foreground"><X className="h-4 w-4" /></button>}
    >
      <div className="space-y-4 font-mono text-xs">
        <div className="flex items-center gap-2">
          <LayerBadge layer={artifact.layer} />
          <SeverityBadge sev={artifact.severity} />
          <span className="ml-auto text-accent">risk {artifact.riskWeight.toFixed(2)}</span>
        </div>
        <Field label="timestamp" value={new Date(artifact.timestamp).toISOString()} />
        <Field label="description" value={artifact.description} multiline />
        <Field label="content_hash (sha-256)" value={artifact.contentHash} copyable onCopy={copy} />
        <Field label="chain_hash" value={artifact.chainHash} copyable onCopy={copy} />
        <div className="rounded border border-border/60 bg-background/60 p-3">
          <div className="mb-1 text-[10px] uppercase tracking-wider text-muted-foreground">interpretation</div>
          <div className="text-foreground">
            Auto-flagged by the ensemble scorer with risk weight <span className="text-accent">{artifact.riskWeight.toFixed(2)}</span>.
            Correlated with adjacent artifacts in the same 5-minute window.
          </div>
        </div>
      </div>
    </Panel>
  );
}

function Field({ label, value, multiline, copyable, onCopy }: { label: string; value: string; multiline?: boolean; copyable?: boolean; onCopy?: (s: string) => void }) {
  return (
    <div>
      <div className="flex items-baseline justify-between">
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
        {copyable && (
          <button onClick={() => onCopy?.(value)} className="text-muted-foreground hover:text-primary"><Copy className="h-3 w-3" /></button>
        )}
      </div>
      <div className={`mt-1 ${multiline ? "" : "truncate"} text-foreground`}>{value}</div>
    </div>
  );
}

function LayerBadge({ layer }: { layer: Layer }) {
  const styles: Record<Layer, React.CSSProperties> = {
    filesystem: { color: "oklch(0.80 0.17 75)",  borderColor: "oklch(0.80 0.17 75 / 0.4)",  background: "oklch(0.80 0.17 75 / 0.12)" },
    eventlog:   { color: "oklch(0.78 0.14 210)", borderColor: "oklch(0.78 0.14 210 / 0.4)", background: "oklch(0.78 0.14 210 / 0.12)" },
    process:    { color: "oklch(0.82 0.18 155)", borderColor: "oklch(0.82 0.18 155 / 0.4)", background: "oklch(0.82 0.18 155 / 0.12)" },
    registry:   { color: "oklch(0.68 0.18 295)", borderColor: "oklch(0.68 0.18 295 / 0.4)", background: "oklch(0.68 0.18 295 / 0.12)" },
  };
  return <span className="inline-block rounded border px-1.5 py-0.5 text-[10px] uppercase" style={styles[layer]}>{layer}</span>;
}

function SeverityBadge({ sev }: { sev: Severity }) {
  const map: Record<Severity, { c: string; bg: string }> = {
    critical: { c: "oklch(0.64 0.24 25)",  bg: "oklch(0.64 0.24 25 / 0.18)" },
    high:     { c: "oklch(0.80 0.17 75)",  bg: "oklch(0.80 0.17 75 / 0.18)" },
    medium:   { c: "oklch(0.78 0.14 210)", bg: "oklch(0.78 0.14 210 / 0.18)" },
    low:      { c: "oklch(0.62 0.018 220)", bg: "oklch(0.62 0.018 220 / 0.18)" },
    info:     { c: "oklch(0.62 0.018 220)", bg: "oklch(0.62 0.018 220 / 0.18)" },
  };
  return <span className="inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase" style={{ color: map[sev].c, background: map[sev].bg }}>{sev}</span>;
}
