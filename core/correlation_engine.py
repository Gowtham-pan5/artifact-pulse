"""Correlation engine for multi-layer forensic timeline analysis."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
from typing import Dict, List

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from database.db_manager import DBManager

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlate artifacts into suspicious temporal activity clusters."""

    def __init__(self, db: DBManager) -> None:
        """Initialize correlation engine with database handle."""
        try:
            self.db = db
            self.super_timeline = pd.DataFrame()
        except Exception:
            logger.exception("Failed to initialize CorrelationEngine")
            raise

    def build_super_timeline(self) -> pd.DataFrame:
        """Build normalized UTC timeline DataFrame from all artifacts."""
        try:
            artifacts = self.db.get_all_artifacts()
            if not artifacts:
                self.super_timeline = pd.DataFrame()
                return self.super_timeline
            df = pd.DataFrame(artifacts)
            df["timestamp"] = pd.to_datetime(df["event_time"], utc=True, errors="coerce")
            df = df.dropna(subset=["timestamp"]).copy()
            keep = [
                "timestamp",
                "artifact_id",
                "source_layer",
                "artifact_type",
                "source_path",
                "content",
                "risk_weight",
            ]
            self.super_timeline = df[keep].sort_values("timestamp", ascending=True)
            logger.info("Super timeline built with %s events", len(self.super_timeline))
            return self.super_timeline
        except Exception:
            logger.exception("Failed building super timeline")
            return pd.DataFrame()

    def find_suspicious_clusters(self, window_minutes: int = 5) -> List[Dict[str, object]]:
        """Find suspicious clusters via fixed-window temporal scoring."""
        clusters: List[Dict[str, object]] = []
        try:
            if self.super_timeline.empty:
                return clusters
            af = pd.DataFrame(self.db.get_antiforensic_events())
            df = self.super_timeline.set_index("timestamp")
            for window_start, group in df.resample(f"{window_minutes}min"):
                if group.empty:
                    continue
                count = len(group)
                avg_risk = float(group["risk_weight"].fillna(0).mean())
                layers = int(group["source_layer"].nunique())
                w_end = (window_start + pd.Timedelta(minutes=window_minutes)).isoformat()
                af_count = 0
                if not af.empty and "event_time" in af.columns:
                    af_times = pd.to_datetime(af["event_time"], utc=True, errors="coerce")
                    af_count = int(
                        ((af_times >= window_start) & (af_times < window_start + pd.Timedelta(minutes=window_minutes))).sum()
                    )
                score = (
                    min(count / 10, 1.0) * 0.25
                    + avg_risk * 0.35
                    + min(layers / 4, 1.0) * 0.25
                    + min(af_count * 0.3, 1.0) * 0.15
                ) * 100
                if score <= 20:
                    continue
                types = set(group["artifact_type"].astype(str).tolist())
                layers_set = set(group["source_layer"].astype(str).tolist())
                high_risk = bool((group["risk_weight"] >= 0.7).any())
                if af_count > 0:
                    attack = "Evidence Tampering & Cover-Up"
                elif "filesystem" in layers_set and "registry" in layers_set:
                    attack = "Data Exfiltration via USB+Web"
                elif "network_connection" in types and high_risk:
                    attack = "Suspicious Network Activity"
                elif "running_process" in types and high_risk:
                    attack = "Malicious Process Execution"
                else:
                    attack = "Anomalous Endpoint Activity"
                top_ids = ",".join(group["artifact_id"].head(5).tolist())
                item = {
                    "cluster_id": f"CL-{window_start.strftime('%Y%m%d%H%M')}",
                    "window_start": window_start.isoformat(),
                    "window_end": w_end,
                    "event_count": count,
                    "suspicion_score": round(score, 2),
                    "attack_type": attack,
                    "layers_involved": ",".join(sorted(layers_set)),
                    "top_artifacts": top_ids,
                    "antiforensic_count": af_count,
                }
                clusters.append(item)
            clusters.sort(key=lambda c: float(c["suspicion_score"]), reverse=True)
            with self.db._conn:
                for c in clusters[:10]:
                    self.db._conn.execute(
                        """
                        INSERT OR REPLACE INTO clusters (
                            cluster_id, case_id, window_start, window_end, event_count,
                            suspicion_score, attack_type, layers_involved, top_artifacts,
                            antiforensic_count, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            c["cluster_id"],
                            self.db._conn.execute("SELECT case_id FROM case_info LIMIT 1").fetchone()[0],
                            c["window_start"],
                            c["window_end"],
                            c["event_count"],
                            c["suspicion_score"],
                            c["attack_type"],
                            c["layers_involved"],
                            c["top_artifacts"],
                            c["antiforensic_count"],
                            datetime.now(UTC).isoformat(),
                        ),
                    )
            return clusters
        except Exception:
            logger.exception("Failed finding suspicious clusters")
            return clusters

    def get_timeline_df(self) -> pd.DataFrame:
        """Return super timeline DataFrame for ML module usage."""
        try:
            return self.super_timeline.copy()
        except Exception:
            logger.exception("Failed returning timeline DataFrame")
            return pd.DataFrame()

    def run_all(self) -> List[Dict[str, object]]:
        """Build timeline and return suspicious clusters."""
        try:
            self.build_super_timeline()
            return self.find_suspicious_clusters()
        except Exception:
            logger.exception("Correlation run_all failed")
            return []


class ProcessBehaviorAnalyzer:
    """
    Heuristic Correlation Engine for Process Behavior Anomaly Detection.
    
    Detects anti-forensic activity via Isolation Forest on process behaviors.
    Optimized for endpoint forensic tools: minimal overhead, fast detection.
    
    Features analyzed:
    - PID: Process Identifier
    - Thread Count: Number of active threads
    - File IO Rate: File operations per second
    - Memory Jump: Sudden memory increase (bytes)
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """
        Initialize ProcessBehaviorAnalyzer.
        
        Args:
            contamination: Expected proportion of anomalies (0.0-1.0). Default 0.1 (10%).
            random_state: Random seed for reproducible results.
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = None
        self.feature_names = ["PID", "Thread_Count", "File_IO_Rate", "Memory_Jump"]
        self.anomalies = pd.DataFrame()
        logger.info("ProcessBehaviorAnalyzer initialized (contamination=%s%%)", contamination * 100)

    def fit(self, data: pd.DataFrame) -> None:
        """
        Train Isolation Forest model on process behavior data.
        
        Args:
            data: DataFrame with columns [PID, Thread_Count, File_IO_Rate, Memory_Jump]
        """
        try:
            # Validate required columns
            if not data.empty:
                missing = set(self.feature_names) - set(data.columns)
                if missing:
                    raise ValueError(f"Missing required features: {missing}")

            if data.empty or len(data) < 5:
                logger.warning("Insufficient data for model training")
                return

            # Feature extraction & normalization
            X = data[self.feature_names].copy()
            X = X.dropna()
            
            if len(X) < 5:
                logger.warning("Insufficient valid data after cleaning")
                return

            # Standardize features (critical for Isolation Forest efficiency)
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)

            # Train Isolation Forest (unsupervised anomaly detection)
            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,  # Balanced: speed vs accuracy
                max_samples="auto",
                random_state=self.random_state,
                n_jobs=-1  # Parallel processing
            )
            self.model.fit(X_scaled)
            logger.info("Model trained on %d process records", len(X))

        except Exception as e:
            logger.exception("Failed to fit model: %s", str(e))
            raise

    def detect_anomalies(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Detect anomalous processes using trained model.
        
        Args:
            data: DataFrame with process behavior features
            
        Returns:
            DataFrame with anomalous processes, sorted by anomaly score (descending).
        """
        try:
            if self.model is None or self.scaler is None:
                logger.error("Model not trained. Call fit() first.")
                return pd.DataFrame()

            # Validate data
            X = data[self.feature_names].copy()
            X = X.dropna()
            
            if X.empty:
                logger.warning("No valid data to analyze")
                return pd.DataFrame()

            # Predict anomalies (-1 = anomaly, 1 = normal)
            X_scaled = self.scaler.transform(X)
            predictions = self.model.predict(X_scaled)
            
            # Get anomaly scores (lower = more anomalous)
            scores = self.model.score_samples(X_scaled)
            
            # Build results DataFrame
            results = X.copy()
            results["Prediction"] = predictions
            results["Anomaly_Score"] = scores
            results["Risk_Level"] = results["Anomaly_Score"].apply(self._risk_level)
            
            # Filter anomalies
            self.anomalies = results[results["Prediction"] == -1].copy()
            self.anomalies = self.anomalies.sort_values("Anomaly_Score", ascending=True)
            
            return self.anomalies

        except Exception as e:
            logger.exception("Anomaly detection failed: %s", str(e))
            return pd.DataFrame()

    @staticmethod
    def _risk_level(score: float) -> str:
        """Classify risk level based on anomaly score."""
        if score < -0.5:
            return "CRITICAL"
        elif score < -0.2:
            return "HIGH"
        elif score < 0.0:
            return "MEDIUM"
        else:
            return "LOW"

    def analyze(self, data: pd.DataFrame) -> Dict[str, object]:
        """
        Complete pipeline: fit model and detect anomalies.
        
        Args:
            data: Process behavior DataFrame
            
        Returns:
            Dictionary with analysis results and anomalous processes
        """
        try:
            logger.info("Starting process behavior analysis...")
            self.fit(data)
            anomalies = self.detect_anomalies(data)
            
            result = {
                "total_processes": len(data),
                "valid_processes": len(data.dropna(subset=self.feature_names)),
                "anomalies_detected": len(anomalies),
                "anomaly_percentage": round(len(anomalies) / len(data) * 100, 2) if len(data) > 0 else 0,
                "critical_count": len(anomalies[anomalies["Risk_Level"] == "CRITICAL"]),
                "high_count": len(anomalies[anomalies["Risk_Level"] == "HIGH"]),
                "anomalous_processes": anomalies.to_dict(orient="records"),
            }
            
            logger.info("Analysis complete: %d anomalies detected", len(anomalies))
            return result

        except Exception as e:
            logger.exception("Analysis pipeline failed: %s", str(e))
            return {
                "error": str(e),
                "total_processes": 0,
                "anomalies_detected": 0,
                "anomalous_processes": [],
            }

    def print_results(self, include_all: bool = False) -> None:
        """
        Print formatted anomaly report.
        
        Args:
            include_all: If True, print all anomalies; if False, print top 10.
        """
        if self.anomalies.empty:
            print("\n✓ No anomalous processes detected.")
            return

        print("\n" + "=" * 90)
        print("ANOMALOUS PROCESS REPORT - ARTIFACT PULSE HEURISTIC CORRELATION ENGINE")
        print("=" * 90)
        
        display_df = self.anomalies if include_all else self.anomalies.head(10)
        
        # Format output
        display_data = []
        for idx, row in display_df.iterrows():
            display_data.append({
                "PID": int(row["PID"]),
                "Threads": int(row["Thread_Count"]),
                "File I/O (ops/s)": f"{row['File_IO_Rate']:.2f}",
                "Memory Jump (MB)": f"{row['Memory_Jump']:.2f}",
                "Risk": row["Risk_Level"],
                "Score": f"{row['Anomaly_Score']:.3f}",
            })
        
        # Print table
        from tabulate import tabulate
        print(tabulate(display_data, headers="keys", tablefmt="grid"))
        
        print(f"\nTotal Anomalies: {len(self.anomalies)}")
        if len(self.anomalies) > 10 and not include_all:
            print(f"(Showing top 10 of {len(self.anomalies)} anomalies)")
        print("=" * 90 + "\n")
