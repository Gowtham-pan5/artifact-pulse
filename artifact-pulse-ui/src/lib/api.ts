/**
 * Artifact-Pulse — Flask Backend API Client
 * All requests go to /api/* which Vite proxies to http://127.0.0.1:5000
 */

const BASE = "";

// ─── Types mirroring Flask JSON responses ────────────────────────────────────

export interface HealthResponse {
  status: string;
  version: string;
  case_id: string;
}

export interface ExtractionStatus {
  running: boolean;
  progress: number;
  stage: string;
  message: string;
  started_at: string | null;
  error: string | null;
  ml_scores: MlScores;
}

export interface MlScores {
  final_suspicion_score?: number;
  severity?: string;
  anomaly_rate?: number;
  total_anomalies?: number;
  isolation_forest_score?: number;
  keyword_hits?: number;
  attack_type_breakdown?: Record<string, number>;
  top_anomaly_explanations?: AnomalyExplanation[];
  global_feature_importance?: FeatureImportance[];
  top_anomalies?: PredictionResult[];
}

export interface PredictionResult {
  artifact_id: string;
  is_anomaly: boolean;
  anomaly_score: number;
  attack_type: string;
  attack_confidence: number;
  combined_risk: number;
  severity: string;
}

export interface AnomalyExplanation {
  artifact_id: string;
  attack_type: string;
  severity: string;
  combined_risk: number;
  summary: string;
  reasons: string[];
}

export interface FeatureImportance {
  feature: string;
  importance: number;
  explanation: string;
}

export interface Artifact {
  artifact_id: number;
  source_layer: string;
  artifact_type: string;
  source_path: string;
  event_time: string;
  risk_weight: number;
  content_hash: string;
  chain_hash: string;
}

export interface StatsResponse {
  total: number;
  total_artifacts: number;
  af_count: number;
  antiforensic: number;
  high_risk_count: number;
  high_risk: number;
  clusters: number;
  layer_breakdown: Record<string, number>;
}

export interface AntiForensicEvent {
  id: number;
  event_type: string;
  severity: string;
  timestamp: string;
  evidence: string;
}

export interface Cluster {
  cluster_id: string;
  suspicion_score: number;
  window_start: string;
  attack_type: string;
  artifact_count?: number;
}

export interface ChainVerification {
  status: string;
  message: string;
  chain_integrity?: boolean;
  master_hash?: string;
}

// ─── API Helpers ────────────────────────────────────────────────────────────

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok && res.status !== 409) throw new Error(`POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

// ─── Public API Functions ────────────────────────────────────────────────────

export const api = {
  /** Check if Flask backend is alive */
  health: () => get<HealthResponse>("/api/health"),

  /** Start the forensic extraction pipeline */
  startExtraction: () => post<{ status: string; case_id: string }>("/api/extraction/start"),

  /** Poll extraction progress (running, progress 0-100, stage, message, ml_scores) */
  extractionStatus: () => get<ExtractionStatus>("/api/extraction/status"),

  /** Get aggregate dashboard stats */
  stats: () => get<StatsResponse>("/api/stats"),

  /** Get all artifacts with optional layer filter and pagination */
  artifacts: (layer?: string, limit = 200, offset = 0) => {
    const params = new URLSearchParams();
    if (layer && layer !== "all") params.set("layer", layer);
    params.set("limit", String(limit));
    params.set("offset", String(offset));
    return get<Artifact[]>(`/api/artifacts?${params.toString()}`);
  },

  /** Get anti-forensic detection events */
  antiforensic: () => get<AntiForensicEvent[]>("/api/antiforensic"),

  /** Get suspicious correlation clusters */
  clusters: () => get<Cluster[]>("/api/clusters"),

  /** Verify the cryptographic chain of custody */
  verifyChain: () => get<ChainVerification>("/api/chain/verify"),

  /** Generate the PDF forensic report */
  generateReport: () => post<{ status: string; path?: string }>("/api/report/generate"),

  /** Download the PDF forensic report */
  downloadReport: () => {
    window.location.href = "/api/report/download";
  },
};
