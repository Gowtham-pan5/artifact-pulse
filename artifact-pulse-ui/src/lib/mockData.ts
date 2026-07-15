/**
 * Mock forensic dataset for Artifact-Pulse demo.
 * Simulates the output of all 7 backend modules.
 */

export type Layer = "filesystem" | "eventlog" | "process" | "registry";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Artifact {
  id: string;
  timestamp: string;
  layer: Layer;
  source: string;
  description: string;
  severity: Severity;
  contentHash: string;
  chainHash: string;
  riskWeight: number;
}

export interface Cluster {
  id: string;
  windowStart: string;
  windowEnd: string;
  artifactCount: number;
  layerDiversity: number;
  suspicionScore: number;
  pattern: string;
  layers: Layer[];
}

export interface AntiForensicEvent {
  id: string;
  timestamp: string;
  technique: string;
  evidence: string;
  severity: Severity;
}

export const caseInfo = {
  caseId: "AP-2026-0419",
  investigator: "Det. R. Sharma",
  examiner: "Forensic Team Alpha",
  acquisitionDate: "2026-04-19T03:42:18Z",
  hostName: "DESKTOP-WIN10-DEVOPS",
  os: "Windows 10 Pro 22H2 (Build 19045.4046)",
  totalArtifacts: 14782,
  masterHash: "a3f9c2e1b4d6789f0a1c5e8b2d4f6a9c1e3b5d7f9a2c4e6b8d0f2a4c6e8b0d2f",
};

export const summaryStats = {
  artifactsExtracted: 14782,
  suspiciousClusters: 7,
  antiForensicEvents: 4,
  overallSuspicion: 87,
  filesScanned: 8421,
  eventsParsed: 3829,
  processesAnalyzed: 142,
  registryKeys: 2390,
};

export const layerBreakdown = [
  { layer: "Filesystem", count: 8421, color: "var(--color-chart-1)" },
  { layer: "Event Logs", count: 3829, color: "var(--color-chart-2)" },
  { layer: "Process", count: 142, color: "var(--color-chart-4)" },
  { layer: "Registry", count: 2390, color: "var(--color-chart-3)" },
];

export const artifacts: Artifact[] = [
  {
    id: "AF-0001",
    timestamp: "2026-04-18T22:14:03Z",
    layer: "eventlog",
    source: "Security.evtx",
    description: "Event 4625 — Failed logon for user 'administrator' from 192.168.1.47",
    severity: "high",
    contentHash: "8f4e2a1b9c7d3e5f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f",
    chainHash: "1a2b3c4d5e6f7890abcdef1234567890fedcba0987654321abcdef0123456789",
    riskWeight: 0.85,
  },
  {
    id: "AF-0002",
    timestamp: "2026-04-18T22:14:47Z",
    layer: "eventlog",
    source: "Security.evtx",
    description: "Event 4624 — Successful logon (Type 10/RDP) for 'administrator'",
    severity: "high",
    contentHash: "9e5f3b2c0d8e4f6a1b3c5d7e9f0a2b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4f6a",
    chainHash: "2b3c4d5e6f7890abcdef1234567890fedcba0987654321abcdef0123456789ab",
    riskWeight: 0.92,
  },
  {
    id: "AF-0003",
    timestamp: "2026-04-18T22:16:12Z",
    layer: "process",
    source: "psutil snapshot",
    description: "powershell.exe spawned with -EncodedCommand flag (PID 4892)",
    severity: "critical",
    contentHash: "af3e2c1b9d7e5f0a4b2c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e4f6b",
    chainHash: "3c4d5e6f7890abcdef1234567890fedcba0987654321abcdef0123456789abcd",
    riskWeight: 0.98,
  },
  {
    id: "AF-0004",
    timestamp: "2026-04-18T22:16:34Z",
    layer: "filesystem",
    source: "Prefetch\\POWERSHELL.EXE-9F3D2A.pf",
    description: "PowerShell prefetch updated — execution count incremented to 47",
    severity: "high",
    contentHash: "bc4d3e2c0a8f6e4d2b0c8e6f4a2b0c8e6f4a2b0c8e6f4a2b0c8e6f4a2b0c8e6f",
    chainHash: "4d5e6f7890abcdef1234567890fedcba0987654321abcdef0123456789abcdef",
    riskWeight: 0.78,
  },
  {
    id: "AF-0005",
    timestamp: "2026-04-18T22:18:21Z",
    layer: "registry",
    source: "HKLM\\System\\USBSTOR",
    description: "New USB device enumerated: Kingston DataTraveler 32GB (S/N: 0014780B...)",
    severity: "medium",
    contentHash: "cd5e4f3a1b9c7e5d3a1b9c7e5d3a1b9c7e5d3a1b9c7e5d3a1b9c7e5d3a1b9c7e",
    chainHash: "5e6f7890abcdef1234567890fedcba0987654321abcdef0123456789abcdef01",
    riskWeight: 0.65,
  },
  {
    id: "AF-0006",
    timestamp: "2026-04-18T22:19:08Z",
    layer: "filesystem",
    source: "Users\\admin\\Downloads\\",
    description: "File created: mimikatz_x64.exe (SHA-256 matches known credential dumper)",
    severity: "critical",
    contentHash: "de6f5a4b2c0d8e6f4a2b0c8e6f4a2b0c8e6f4a2b0c8e6f4a2b0c8e6f4a2b0c8e",
    chainHash: "6f7890abcdef1234567890fedcba0987654321abcdef0123456789abcdef0123",
    riskWeight: 0.99,
  },
  {
    id: "AF-0007",
    timestamp: "2026-04-18T22:21:45Z",
    layer: "eventlog",
    source: "Microsoft-Windows-PowerShell/Operational",
    description: "Event 4104 — ScriptBlock logged: Invoke-Mimikatz; sekurlsa::logonpasswords",
    severity: "critical",
    contentHash: "ef7a6b5c3d1e9f7a5c3e1f9a7c5e3a1f9c7e5a3f1c9e7a5c3e1f9a7c5e3a1f9c",
    chainHash: "7890abcdef1234567890fedcba0987654321abcdef0123456789abcdef012345",
    riskWeight: 0.99,
  },
  {
    id: "AF-0008",
    timestamp: "2026-04-18T22:24:11Z",
    layer: "process",
    source: "psutil + ctypes",
    description: "ccleaner64.exe loaded with -auto flag — wiping tool execution detected",
    severity: "critical",
    contentHash: "fa8b7c6d4e2f0a8b6d4f2a0b8d6f4a2b0d8f6a4b2d0f8a6b4d2f0a8b6d4f2a0b",
    chainHash: "890abcdef1234567890fedcba0987654321abcdef0123456789abcdef0123456",
    riskWeight: 0.95,
  },
  {
    id: "AF-0009",
    timestamp: "2026-04-18T22:25:39Z",
    layer: "eventlog",
    source: "Security.evtx",
    description: "Event 1102 — Audit log was cleared by user 'administrator'",
    severity: "critical",
    contentHash: "0b9c8d7e5f3a1b9d7f5a3b1d9f7a5b3d1f9a7b5d3f1a9b7d5f3a1b9d7f5a3b1d",
    chainHash: "90abcdef1234567890fedcba0987654321abcdef0123456789abcdef01234567",
    riskWeight: 1.0,
  },
  {
    id: "AF-0010",
    timestamp: "2026-04-18T22:26:02Z",
    layer: "filesystem",
    source: "$Recycle.Bin\\S-1-5-21-...",
    description: "Recycle Bin emptied — 142 entries removed (correlated with wiping event)",
    severity: "high",
    contentHash: "1c0d9e8f6a4b2c0e8f6a4c2e0a8f6c4a2e0c8a6f4c2a0e8f6c4a2e0c8a6f4c2a",
    chainHash: "0abcdef1234567890fedcba0987654321abcdef0123456789abcdef012345678",
    riskWeight: 0.88,
  },
];

export const clusters: Cluster[] = [
  {
    id: "CL-001",
    windowStart: "2026-04-18T22:14:00Z",
    windowEnd: "2026-04-18T22:19:00Z",
    artifactCount: 23,
    layerDiversity: 4,
    suspicionScore: 94,
    pattern: "Initial Access → Credential Access (RDP brute → mimikatz drop)",
    layers: ["eventlog", "process", "filesystem", "registry"],
  },
  {
    id: "CL-002",
    windowStart: "2026-04-18T22:19:00Z",
    windowEnd: "2026-04-18T22:24:00Z",
    artifactCount: 18,
    layerDiversity: 3,
    suspicionScore: 89,
    pattern: "Execution → Defense Evasion (PowerShell encoded payload)",
    layers: ["process", "eventlog", "filesystem"],
  },
  {
    id: "CL-003",
    windowStart: "2026-04-18T22:24:00Z",
    windowEnd: "2026-04-18T22:27:00Z",
    artifactCount: 31,
    layerDiversity: 4,
    suspicionScore: 98,
    pattern: "Anti-Forensic Sequence (CCleaner → log clear → recycle bin wipe)",
    layers: ["process", "eventlog", "filesystem", "registry"],
  },
  {
    id: "CL-004",
    windowStart: "2026-04-18T22:27:00Z",
    windowEnd: "2026-04-18T22:32:00Z",
    artifactCount: 9,
    layerDiversity: 2,
    suspicionScore: 67,
    pattern: "Persistence (Autorun registry modification)",
    layers: ["registry", "filesystem"],
  },
  {
    id: "CL-005",
    windowStart: "2026-04-18T22:32:00Z",
    windowEnd: "2026-04-18T22:37:00Z",
    artifactCount: 14,
    layerDiversity: 3,
    suspicionScore: 73,
    pattern: "Lateral Movement Reconnaissance (NetworkList enumeration)",
    layers: ["registry", "process", "eventlog"],
  },
  {
    id: "CL-006",
    windowStart: "2026-04-18T22:37:00Z",
    windowEnd: "2026-04-18T22:42:00Z",
    artifactCount: 6,
    layerDiversity: 2,
    suspicionScore: 58,
    pattern: "Data Staging (Downloads folder activity)",
    layers: ["filesystem", "process"],
  },
  {
    id: "CL-007",
    windowStart: "2026-04-18T22:42:00Z",
    windowEnd: "2026-04-18T22:47:00Z",
    artifactCount: 11,
    layerDiversity: 3,
    suspicionScore: 81,
    pattern: "Exfiltration Indicators (USB enumeration + file copies)",
    layers: ["registry", "filesystem", "eventlog"],
  },
];

export const antiForensicEvents: AntiForensicEvent[] = [
  {
    id: "AFE-01",
    timestamp: "2026-04-18T22:24:11Z",
    technique: "Wiping Tool Execution",
    evidence: "ccleaner64.exe found in Prefetch with execution timestamp",
    severity: "critical",
  },
  {
    id: "AFE-02",
    timestamp: "2026-04-18T22:25:39Z",
    technique: "Audit Log Clearing",
    evidence: "Event ID 1102 — Security log explicitly cleared",
    severity: "critical",
  },
  {
    id: "AFE-03",
    timestamp: "2026-04-18T22:26:02Z",
    technique: "Recycle Bin Wipe",
    evidence: "$I metadata gap detected — 142 entries removed in single op",
    severity: "high",
  },
  {
    id: "AFE-04",
    timestamp: "2026-04-18T22:28:17Z",
    technique: "Timestomping",
    evidence: "$MFT vs $STANDARD_INFO timestamp divergence on 7 files",
    severity: "high",
  },
];

export const timelineData = clusters.map((c) => ({
  time: new Date(c.windowStart).toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }),
  score: c.suspicionScore,
  artifacts: c.artifactCount,
  cluster: c.id,
}));

export const modules = [
  {
    id: 1,
    name: "Filesystem Extractor",
    file: "filesystem_extractor.py",
    icon: "HardDrive",
    description:
      "Parses Chrome/Firefox SQLite history, Windows Prefetch, LNK files, Recycle Bin $I metadata, Jump Lists, Sticky Notes, and thumbnail caches.",
    capabilities: ["Browser DB parsing", "Prefetch analysis", "LNK extraction", "Jump Lists"],
  },
  {
    id: 2,
    name: "Event Log Extractor",
    file: "eventlog_extractor.py",
    icon: "ScrollText",
    description:
      "EVTX parsing via python-evtx. Captures Security (4624/4625/1102), System, PowerShell Operational, USBSTOR registry, and NetworkList history.",
    capabilities: ["EVTX parsing", "USB history", "PowerShell logs", "Network history"],
  },
  {
    id: 3,
    name: "Process Extractor",
    file: "process_extractor.py",
    icon: "Cpu",
    description:
      "Live process snapshot via psutil. Captures network connections, open file handles, loaded DLLs (ctypes), clipboard, and active sessions.",
    capabilities: ["Live snapshot", "Network conns", "DLL inspection", "Clipboard capture"],
  },
  {
    id: 4,
    name: "Anti-Forensic Detector",
    file: "antiforensic_detector.py",
    icon: "ShieldAlert",
    description:
      "Detects wiping tools (CCleaner/BleachBit/Eraser), audit log clearing (1102), prefetch disabling, VSS shadow deletion, and timestomping.",
    capabilities: ["Wiper detection", "Log-clear alerts", "Timestomp checks", "VSS audit"],
  },
  {
    id: 5,
    name: "Correlation Engine",
    file: "correlation_engine.py",
    icon: "Network",
    description:
      "Pandas super-timeline merge across all 4 layers. 5-minute rolling windows, weighted suspicion scoring, attack pattern classification.",
    capabilities: ["Cross-layer merge", "Rolling windows", "Pattern classification"],
  },
  {
    id: 6,
    name: "ML Anomaly Scorer",
    file: "ml_scorer.py",
    icon: "Brain",
    description:
      "Isolation Forest (contamination=0.05) + KMeans clustering + TF-IDF keyword vectorizer. Weighted final score across three orthogonal signals.",
    capabilities: ["Isolation Forest", "KMeans (k=5)", "TF-IDF keywords"],
  },
  {
    id: 7,
    name: "Evidence Sealer",
    file: "evidence_sealer.py",
    icon: "FileLock",
    description:
      "SHA-256 per-artifact content hashing, Merkle-style chain hashing, master hash. NIST SP 800-86 + Section 65B IT Act 2000 compliant.",
    capabilities: ["SHA-256 chain", "Merkle ledger", "Section 65B"],
  },
];

export const evaluatorQA = [
  {
    q: "Autopsy already does forensic extraction — why build this?",
    a: "Autopsy excels at filesystem carving but lacks anti-forensic sequence detection, ML anomaly scoring, cross-layer temporal correlation, and Section 65B-compliant output. Artifact-Pulse fills those specific gaps in a single unified pipeline.",
  },
  {
    q: "Volatility is superior for process analysis.",
    a: "Correct — Volatility is unmatched for deep memory forensics. We use psutil for live process triage as part of broader multi-layer analysis. Volatility integration is on our Phase 2 roadmap as a complementary engine.",
  },
  {
    q: "How does Isolation Forest avoid false positives?",
    a: "We set contamination=0.05 (5% expected anomaly rate) and combine it with risk-weight heuristics and KMeans density scoring. The final score is a weighted ensemble across three orthogonal signals — not a single model — which materially reduces FPR.",
  },
  {
    q: "Is the chain of custody legally admissible?",
    a: "Yes. The SHA-256 sealed append-only SQLite ledger satisfies Section 65B of the IT Act 2000. Each artifact carries a content_hash and chain_hash; tampering with any record breaks the entire chain and is detectable via the master hash.",
  },
  {
    q: "Why Isolation Forest over DBSCAN or LOF?",
    a: "Isolation Forest performs better on high-dimensional sparse forensic feature vectors and scales linearly with sample count. DBSCAN struggles with variable density across attack phases; LOF is O(n²) which is impractical at our artifact volumes (10k+).",
  },
  {
    q: "What's technically novel here?",
    a: "The combination is novel — no existing open-source tool integrates multi-layer simultaneous extraction, anti-forensic sequence detection, heuristic temporal correlation, ML behavioral scoring, AND Indian legal compliance in one pipeline. We verified this gap on Google Scholar.",
  },
];

// ===== Pipeline steps =====
export type PipelineStatus = "pending" | "running" | "done" | "failed";
export interface PipelineStep {
  id: number;
  key: string;
  name: string;
  module: string;
  description: string;
  icon: string;
  logs: string[];
}
export const pipelineSteps: PipelineStep[] = [
  {
    id: 1, key: "fs", name: "Filesystem Scan", module: "filesystem_extractor.py",
    icon: "HardDrive",
    description: "Parse NTFS $MFT, Prefetch, LNK, Recycle Bin, browser SQLite",
    logs: [
      "[+] mounting volume \\\\.\\PhysicalDrive0 read-only",
      "[+] parsing $MFT  (records=842,193)",
      "[+] enumerating C:\\Windows\\Prefetch  (entries=189)",
      "[+] parsing Chrome\\User Data\\Default\\History  (3,412 rows)",
      "[+] reading Recycle Bin $I metadata  (entries=142)",
      "[✓] filesystem layer complete  (artifacts=8,421  elapsed=12.4s)",
    ],
  },
  {
    id: 2, key: "evtx", name: "Event Log Parse", module: "eventlog_extractor.py",
    icon: "ScrollText",
    description: "EVTX channels — Security, System, PowerShell Operational",
    logs: [
      "[+] opening Security.evtx  (size=128MB)",
      "[+] indexing EventIDs: 4624, 4625, 4688, 1102, 4104",
      "[!] EventID 1102 detected — audit log clear at 22:25:39",
      "[+] parsing Microsoft-Windows-PowerShell/Operational.evtx",
      "[!] EventID 4104 encoded ScriptBlock matches 'Invoke-Mimikatz'",
      "[✓] eventlog layer complete  (events=3,829  elapsed=8.1s)",
    ],
  },
  {
    id: 3, key: "proc", name: "Process Snapshot", module: "process_extractor.py",
    icon: "Cpu",
    description: "Live psutil + ctypes DLL enumeration + netstat",
    logs: [
      "[+] enumerating live processes via psutil  (count=142)",
      "[+] resolving network connections  (ESTABLISHED=18, LISTEN=24)",
      "[!] powershell.exe PID 4892  flag=-EncodedCommand",
      "[!] ccleaner64.exe PID 5104  flag=-auto",
      "[+] reading clipboard contents  (size=412 bytes)",
      "[✓] process layer complete  (artifacts=142  elapsed=2.7s)",
    ],
  },
  {
    id: 4, key: "af", name: "Anti-Forensic Check", module: "antiforensic_detector.py",
    icon: "ShieldAlert",
    description: "Wiping tool, log-clear, timestomp, VSS deletion signatures",
    logs: [
      "[+] scanning prefetch for known wipers",
      "[!] CCLEANER64.EXE-*.pf  matched (ts=22:24:11)",
      "[!] Security log EventID 1102 — explicit clear",
      "[+] diff $MFT vs $STANDARD_INFORMATION timestamps",
      "[!] 7 files exhibit timestamp divergence (timestomp)",
      "[!] vssadmin delete shadows /all detected in cmdline history",
      "[✓] anti-forensic check complete  (alerts=4  elapsed=4.0s)",
    ],
  },
  {
    id: 5, key: "corr", name: "Cross-Layer Correlation", module: "correlation_engine.py",
    icon: "Network",
    description: "Pandas merge over 4 layers · 5-min rolling window scoring",
    logs: [
      "[+] building super-timeline (rows=14,782)",
      "[+] rolling window=300s  step=60s",
      "[+] tagging clusters by attack-phase heuristics",
      "[+] cluster CL-001 score=94  (Initial Access → Credential Access)",
      "[+] cluster CL-003 score=98  (Anti-Forensic Sequence)",
      "[✓] correlation complete  (clusters=7  elapsed=3.2s)",
    ],
  },
  {
    id: 6, key: "ml", name: "ML Anomaly Scoring", module: "ml_scorer.py",
    icon: "Brain",
    description: "Isolation Forest + KMeans(k=5) + TF-IDF keyword vectorizer",
    logs: [
      "[+] feature extraction  (dims=64)",
      "[+] fitting IsolationForest  (contamination=0.05  trees=128)",
      "[+] fitting KMeans  (k=5  inertia=4218.7)",
      "[+] TF-IDF vocab=412 terms",
      "[+] ensemble weighted score (0.4 ISO + 0.3 KMEANS + 0.3 TFIDF)",
      "[✓] ML scoring complete  (top_anomaly=AF-0009  score=0.99)",
    ],
  },
  {
    id: 7, key: "seal", name: "Chain-of-Custody Hashing", module: "evidence_sealer.py",
    icon: "FileLock",
    description: "SHA-256 per-artifact + Merkle chain + master hash · Section 65B",
    logs: [
      "[+] computing SHA-256 for 14,782 artifacts",
      "[+] building Merkle chain  (depth=14)",
      "[+] sealing append-only SQLite ledger",
      "[+] master_hash=" + caseInfo.masterHash.slice(0, 32) + "…",
      "[✓] evidence sealed  (Section 65B IT Act 2000 compliant)",
    ],
  },
];

// ===== Activity feed (terminal-style scroll) =====
export const activityFeed = [
  { ts: "22:47:18", level: "info", msg: "[seal] master_hash committed → ledger.db" },
  { ts: "22:47:14", level: "warn", msg: "[ml] anomaly_score=0.99 on AF-0009 (audit log clear)" },
  { ts: "22:47:09", level: "crit", msg: "[af] timestomp divergence on 7 files (\\Users\\admin)" },
  { ts: "22:47:01", level: "info", msg: "[corr] cluster CL-003 promoted score 89→98" },
  { ts: "22:46:55", level: "warn", msg: "[proc] suspicious cmdline: powershell -EncodedCommand …" },
  { ts: "22:46:51", level: "info", msg: "[evtx] indexed 3,829 events across 4 channels" },
  { ts: "22:46:47", level: "crit", msg: "[evtx] EventID 1102 — audit log cleared by 'administrator'" },
  { ts: "22:46:42", level: "info", msg: "[fs] parsed 189 Prefetch entries" },
  { ts: "22:46:38", level: "warn", msg: "[fs] mimikatz_x64.exe SHA-256 matches IOC db" },
  { ts: "22:46:33", level: "info", msg: "[fs] $MFT enumeration 842,193 records" },
  { ts: "22:46:29", level: "info", msg: "[engine] worker pool=4 spawned" },
  { ts: "22:46:24", level: "info", msg: "[engine] case AP-2026-0419 attached → DESKTOP-WIN10-DEVOPS" },
] as const;

// ===== Reports =====
export interface Report {
  id: string;
  caseId: string;
  title: string;
  generatedAt: string;
  investigator: string;
  pages: number;
  sizeKb: number;
  artifacts: number;
  hash: string;
  verified: boolean;
}
export const reports: Report[] = [
  {
    id: "RPT-2026-0419-A", caseId: "AP-2026-0419",
    title: "Triage Report — DESKTOP-WIN10-DEVOPS (Full)",
    generatedAt: "2026-04-19T04:18:00Z", investigator: "Det. R. Sharma",
    pages: 47, sizeKb: 2841, artifacts: 14782,
    hash: "a3f9c2e1b4d6789f0a1c5e8b2d4f6a9c1e3b5d7f9a2c4e6b8d0f2a4c6e8b0d2f",
    verified: true,
  },
  {
    id: "RPT-2026-0419-B", caseId: "AP-2026-0419",
    title: "Anti-Forensic Findings — Section 65B Annex",
    generatedAt: "2026-04-19T04:22:00Z", investigator: "Det. R. Sharma",
    pages: 14, sizeKb: 612, artifacts: 4,
    hash: "b8e7d6c5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7",
    verified: true,
  },
  {
    id: "RPT-2026-0412-A", caseId: "AP-2026-0412",
    title: "Triage Report — LAB-FIN-WS04",
    generatedAt: "2026-04-12T19:02:00Z", investigator: "Det. M. Iyer",
    pages: 31, sizeKb: 1820, artifacts: 9214,
    hash: "c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6",
    verified: true,
  },
  {
    id: "RPT-2026-0408-A", caseId: "AP-2026-0408",
    title: "Triage Report — HR-LAPTOP-22 (Preliminary)",
    generatedAt: "2026-04-08T11:44:00Z", investigator: "Det. A. Khan",
    pages: 22, sizeKb: 1108, artifacts: 5471,
    hash: "d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5",
    verified: false,
  },
];

// ===== Anomaly scatter points =====
export interface AnomalyPoint {
  id: string;
  timeMin: number;     // minutes from t0
  score: number;       // 0..1
  cluster: number;     // 0..4 (kmeans)
  reasons: string[];
  artifactId: string;
}
export const anomalyPoints: AnomalyPoint[] = [
  { id: "AP-01", timeMin: 0, score: 0.85, cluster: 0, reasons: ["failed_logon_burst", "off_hours"], artifactId: "AF-0001" },
  { id: "AP-02", timeMin: 0.7, score: 0.92, cluster: 0, reasons: ["rdp_logon_post_failures"], artifactId: "AF-0002" },
  { id: "AP-03", timeMin: 2.2, score: 0.98, cluster: 1, reasons: ["powershell_encoded", "rare_parent_chain"], artifactId: "AF-0003" },
  { id: "AP-04", timeMin: 2.5, score: 0.78, cluster: 1, reasons: ["prefetch_spike"], artifactId: "AF-0004" },
  { id: "AP-05", timeMin: 4.3, score: 0.65, cluster: 2, reasons: ["usb_enumeration_after_hours"], artifactId: "AF-0005" },
  { id: "AP-06", timeMin: 5.1, score: 0.99, cluster: 3, reasons: ["ioc_hash_match", "credential_dumper_path"], artifactId: "AF-0006" },
  { id: "AP-07", timeMin: 7.7, score: 0.99, cluster: 3, reasons: ["script_block_keyword:mimikatz"], artifactId: "AF-0007" },
  { id: "AP-08", timeMin: 10.2, score: 0.95, cluster: 4, reasons: ["wiper_signature", "rare_binary"], artifactId: "AF-0008" },
  { id: "AP-09", timeMin: 11.6, score: 1.0, cluster: 4, reasons: ["audit_log_clear", "single_actor"], artifactId: "AF-0009" },
  { id: "AP-10", timeMin: 12.0, score: 0.88, cluster: 4, reasons: ["bulk_delete_correlated"], artifactId: "AF-0010" },
];
