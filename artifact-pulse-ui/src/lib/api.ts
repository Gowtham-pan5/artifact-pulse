/**
 * API client for Artifact-Pulse backend (Flask on port 5000)
 * Proxied through Vite dev server in development
 */

const API_BASE = '/api';

async function fetchJson<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

export const api = {
  // Dashboard / Summary
  getStats: () => fetchJson<{
    layer_breakdown: Record<string, number>;
    total: number;
    af_count: number;
    high_risk_count: number;
    total_artifacts: number;
    antiforensic: number;
    high_risk: number;
    clusters: number;
  }>('/stats'),

  // Artifacts
  getArtifacts: (params?: { limit?: number; offset?: number; severity?: string; layer?: string }) => {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', String(params.limit));
    if (params?.offset) search.set('offset', String(params.offset));
    if (params?.severity) search.set('severity', params.severity);
    if (params?.layer) search.set('layer', params.layer);
    const qs = search.toString();
    return fetchJson<{ artifacts: any[]; total: number }>(`/artifacts${qs ? `?${qs}` : ''}`);
  },

  // Anomalies / Clusters
  getClusters: () => fetchJson<{ clusters: any[] }>('/clusters'),

  // Anti-Forensic
  getAntiForensic: () => fetchJson<{ antiforensic: any[] }>('/antiforensic'),

  // Chain of Custody
  verifyChain: () => fetchJson<{ integrity: boolean; status: string; message: string; master_hash: string }>('/chain/verify'),

  // Pipeline
  getPipelineStatus: () => fetchJson<{ steps: any[] }>('/pipeline/status'),

  // ML
  getMlFeatureImportance: () => fetchJson<any[]>('/ml/feature-importance'),
  getMlExplanations: () => fetchJson<any[]>('/ml/explanations'),
  getMlAttackBreakdown: () => fetchJson<any>('/ml/attack-breakdown'),
  getMlTrainingInfo: () => fetchJson<any>('/ml/training-info'),

  // Reports
  generateReport: () => fetchJson<{ status: string; path: string }>('/report/generate', { method: 'POST' }),
  downloadReport: () => `${API_BASE}/report/download`,
};

// Type definitions matching backend response shapes
export interface BackendArtifact {
  id: string;
  timestamp: string;
  source_layer: string;
  source: string;
  description: string;
  severity: string;
  content_hash: string;
  chain_hash: string;
  risk_weight: number;
}

export interface BackendCluster {
  id: string;
  window_start: string;
  window_end: string;
  artifact_count: number;
  layer_diversity: number;
  suspicion_score: number;
  pattern: string;
  layers: string[];
}

export interface BackendAntiForensicEvent {
  id: string;
  timestamp: string;
  technique: string;
  evidence: string;
  severity: string;
}

export interface BackendStats {
  layer_breakdown: Record<string, number>;
  total: number;
  af_count: number;
  high_risk_count: number;
  total_artifacts: number;
  antiforensic: number;
  high_risk: number;
  clusters: number;
}