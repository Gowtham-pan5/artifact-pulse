import { useQuery } from "@tanstack/react-query";
import { api, type BackendArtifact, type BackendCluster, type BackendAntiForensicEvent, type BackendStats } from "../lib/api";
import type { Artifact, Layer, Severity, Cluster, AntiForensicEvent } from "../lib/mockData";
export type { Artifact, Layer, Severity, Cluster, AntiForensicEvent } from "../lib/mockData";

/**
 * Transform backend artifact format to frontend format
 */
function transformBackendArtifact(a: BackendArtifact): Artifact {
  // Map backend source_layer to our layer type
  const layerMap: Record<string, Layer> = {
    filesystem: "filesystem",
    eventlog: "eventlog",
    process: "process",
    registry: "registry",
  };
  
  const severityMap: Record<string, Severity> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "low",
  };

  return {
    id: a.id,
    timestamp: a.timestamp,
    layer: layerMap[a.source_layer] ?? "filesystem",
    source: a.source,
    description: a.description,
    severity: severityMap[a.severity] ?? "low",
    contentHash: a.content_hash,
    chainHash: a.chain_hash,
    riskWeight: a.risk_weight,
  };
}

function transformBackendCluster(c: BackendCluster): Cluster {
  const layerMap: Record<string, Layer> = {
    filesystem: "filesystem",
    eventlog: "eventlog",
    process: "process",
    registry: "registry",
  };
  
  return {
    id: c.id,
    windowStart: c.window_start,
    windowEnd: c.window_end,
    artifactCount: c.artifact_count,
    layerDiversity: c.layer_diversity,
    suspicionScore: c.suspicion_score,
    pattern: c.pattern,
    layers: c.layers.map(l => layerMap[l] ?? "filesystem"),
  };
}

function transformBackendAntiForensic(e: BackendAntiForensicEvent): AntiForensicEvent {
  const severityMap: Record<string, Severity> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    info: "low",
  };
  
  return {
    id: e.id,
    timestamp: e.timestamp,
    technique: e.technique,
    evidence: e.evidence,
    severity: severityMap[e.severity] ?? "low",
  };
}

/**
 * React Query hooks for API data
 */
export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: api.getStats,
    staleTime: 30000,
  });
}

export function useArtifacts(params?: { limit?: number; offset?: number; severity?: string; layer?: string }) {
  return useQuery({
    queryKey: ["artifacts", params],
    queryFn: () => api.getArtifacts(params),
    staleTime: 30000,
  });
}

export function useClusters() {
  return useQuery({
    queryKey: ["clusters"],
    queryFn: api.getClusters,
    staleTime: 30000,
  });
}

export function useAntiForensic() {
  return useQuery({
    queryKey: ["antiforensic"],
    queryFn: api.getAntiForensic,
    staleTime: 30000,
  });
}

export function useChainVerify() {
  return useQuery({
    queryKey: ["chain-verify"],
    queryFn: api.verifyChain,
    staleTime: 60000,
  });
}

export function transformArtifacts(artifacts: BackendArtifact[]): Artifact[] {
  return artifacts.map(transformBackendArtifact);
}

export function transformClusters(clusters: BackendCluster[]): Cluster[] {
  return clusters.map(transformBackendCluster);
}

export function transformAntiForensic(events: BackendAntiForensicEvent[]): AntiForensicEvent[] {
  return events.map(transformBackendAntiForensic);
}

export function transformStats(s: BackendStats) {
  return {
    artifactsExtracted: s.total_artifacts ?? s.total ?? 0,
    suspiciousClusters: s.clusters ?? 0,
    antiForensicEvents: s.antiforensic ?? s.af_count ?? 0,
    overallSuspicion: Math.min(100, Math.round(((s.high_risk ?? 0) / Math.max(1, s.total ?? 1)) * 100)),
  };
}