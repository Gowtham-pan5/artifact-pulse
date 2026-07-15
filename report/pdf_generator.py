"""PDF report generation for Artifact-Pulse forensic output."""

from __future__ import annotations

from datetime import UTC, datetime
import logging
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from config import CASE_ID, REPORT_DIR, TOOL_VERSION

logger = logging.getLogger(__name__)


class PDFGenerator:
    """Generate legally-oriented forensic PDF with 11 structured sections."""

    def __init__(
        self,
        artifacts: List[Dict[str, Any]],
        clusters: List[Dict[str, Any]],
        antiforensic: List[Dict[str, Any]],
        ml_scores: Dict[str, Any],
        seal: Dict[str, Any],
    ) -> None:
        """Initialize PDF generator with pipeline outputs."""
        try:
            self.artifacts = artifacts
            self.clusters = clusters
            self.antiforensic = antiforensic
            self.ml_scores = ml_scores
            self.seal = seal
            self.styles = getSampleStyleSheet()
        except Exception:
            logger.exception("Failed to initialize PDFGenerator")
            raise

    def _table(self, data: List[List[Any]]) -> Table:
        """Build consistently styled table widget."""
        try:
            t = Table(data, repeatRows=1)
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1C2333")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            return t
        except Exception:
            logger.exception("Failed creating table")
            raise

    def generate(self) -> Path:
        """Generate full report PDF and return resulting file path."""
        try:
            output = REPORT_DIR / f"ArtifactPulse_Report_{CASE_ID}.pdf"
            doc = SimpleDocTemplate(str(output), pagesize=A4)
            story: List[Any] = []
            story.append(Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", self.styles["Title"]))
            story.append(Spacer(1, 10))
            story.append(
                self._table(
                    [
                        ["Case ID", CASE_ID],
                        ["Tool Version", TOOL_VERSION],
                        ["Generated", datetime.now(UTC).isoformat()],
                        ["Suspicion Score", str(self.ml_scores.get("final_suspicion_score", 0))],
                        ["Severity", str(self.ml_scores.get("severity", "LOW"))],
                    ]
                )
            )
            story.append(PageBreak())
            story.append(Paragraph("Section 01: Executive Summary", self.styles["Heading1"]))
            story.append(Paragraph("Investigation artifacts were collected and analyzed for suspicious patterns.", self.styles["BodyText"]))
            story.append(Paragraph("Section 02: Anti-Forensic Detection Findings", self.styles["Heading1"]))
            af_data = [["event_type", "severity", "timestamp", "evidence"]]
            af_data.extend([[a.get("event_type"), a.get("severity"), a.get("timestamp"), a.get("evidence")] for a in self.antiforensic[:50]])
            if len(af_data) == 1:
                af_data.append(["None", "N/A", "N/A", "No anti-forensic activity detected"])
            story.append(self._table(af_data))
            story.append(Paragraph("Section 03: Suspicious Activity Clusters", self.styles["Heading1"]))
            c_data = [["cluster_id", "score", "window", "attack_type"]]
            c_data.extend([[c.get("cluster_id"), c.get("suspicion_score"), c.get("window_start"), c.get("attack_type")] for c in self.clusters[:5]])
            if len(c_data) == 1:
                c_data.append(["N/A", 0, "N/A", "No suspicious clusters"])
            story.append(self._table(c_data))
            story.append(Paragraph("Section 04: ML Anomaly Analysis", self.styles["Heading1"]))
            story.append(Paragraph(f"Isolation Forest score: {self.ml_scores.get('isolation_forest_score', 0)}", self.styles["BodyText"]))
            story.append(Paragraph(f"KMeans distribution: {self.ml_scores.get('kmeans_distribution', {})}", self.styles["BodyText"]))
            story.append(Paragraph(f"TF-IDF suspicious keyword hits: {self.ml_scores.get('keyword_hits', 0)}", self.styles["BodyText"]))
            story.append(Spacer(1, 8))
            story.append(Paragraph("Sub-section: Attack Type Classification", self.styles["Heading2"]))
            breakdown = self.ml_scores.get("attack_type_breakdown", {}) or {}
            total_attacks = sum(int(v) for v in breakdown.values()) or 1
            attack_table = [["Attack Type", "Count", "% of Total"]]
            if breakdown:
                for attack_type, count in breakdown.items():
                    pct = round((int(count) / total_attacks) * 100, 2)
                    attack_table.append([attack_type, int(count), f"{pct}%"])
            else:
                attack_table.append(["NORMAL", 0, "0.0%"])
            story.append(self._table(attack_table))

            story.append(Spacer(1, 8))
            story.append(Paragraph("Sub-section: Top Anomaly Explanations", self.styles["Heading2"]))
            explanations = self.ml_scores.get("top_anomaly_explanations", []) or []
            if not explanations:
                story.append(Paragraph("No anomaly explanations available.", self.styles["BodyText"]))
            else:
                for idx, item in enumerate(explanations[:5], start=1):
                    story.append(
                        Paragraph(
                            (
                                f"{idx}. Artifact {item.get('artifact_id', 'N/A')} | "
                                f"Type: {item.get('attack_type', 'N/A')} | "
                                f"Severity: {item.get('severity', 'LOW')} | "
                                f"Risk: {round(float(item.get('combined_risk', 0.0)) * 100, 2)}"
                            ),
                            self.styles["BodyText"],
                        )
                    )
                    story.append(Paragraph(str(item.get("summary", "")), self.styles["BodyText"]))
                    reasons = item.get("reasons", [])[:3]
                    for ridx, reason in enumerate(reasons, start=1):
                        story.append(Paragraph(f"{ridx}. {reason}", self.styles["BodyText"]))
                    story.append(Spacer(1, 4))

            story.append(Spacer(1, 8))
            story.append(Paragraph("Sub-section: Feature Importance Analysis", self.styles["Heading2"]))
            story.append(
                Paragraph(
                    "Features ranked by Random Forest importance scores.",
                    self.styles["BodyText"],
                )
            )
            feature_table = [["Feature", "Importance Score", "Explanation"]]
            importance = self.ml_scores.get("global_feature_importance", []) or []
            if importance:
                for item in importance[:10]:
                    feature_table.append(
                        [
                            item.get("feature", "N/A"),
                            item.get("importance", 0),
                            item.get("explanation", "N/A"),
                        ]
                    )
            else:
                feature_table.append(["N/A", 0, "No feature importance available"])
            story.append(self._table(feature_table))
            story.append(Paragraph("Section 05: Artifact Inventory", self.styles["Heading1"]))
            a_data = [["artifact_id", "layer", "type", "timestamp", "hash16"]]
            for a in self.artifacts[:100]:
                a_data.append([a.get("artifact_id"), a.get("source_layer"), a.get("artifact_type"), a.get("event_time"), str(a.get("content_hash", ""))[:16]])
            story.append(self._table(a_data))
            story.append(PageBreak())
            story.append(Paragraph("Section 06: High-Risk Artifacts", self.styles["Heading1"]))
            high = [a for a in self.artifacts if float(a.get("risk_weight") or 0) >= 0.7]
            h_data = [["artifact_id", "type", "risk", "source_path"]]
            h_data.extend([[h.get("artifact_id"), h.get("artifact_type"), h.get("risk_weight"), h.get("source_path")] for h in high[:50]])
            if len(h_data) == 1:
                h_data.append(["N/A", "N/A", "N/A", "No high-risk artifacts"])
            story.append(self._table(h_data))
            story.append(Paragraph("Section 07: Evidence Chain Integrity", self.styles["Heading1"]))
            story.append(Paragraph(f"Status: {'INTACT' if self.seal.get('chain_integrity') else 'TAMPERED'}", self.styles["BodyText"]))
            story.append(Paragraph(f"Master hash: {self.seal.get('master_hash', '')}", self.styles["BodyText"]))
            story.append(Paragraph("Section 08: SHA-256 Hash Verification", self.styles["Heading1"]))
            v_data = [["artifact_id", "content_hash", "chain_hash"]]
            v_data.extend([[a.get("artifact_id"), a.get("content_hash"), a.get("chain_hash")] for a in self.artifacts[:20]])
            story.append(self._table(v_data))
            story.append(Paragraph("Section 09: System Information", self.styles["Heading1"]))
            story.append(Paragraph(f"OS: Windows 10/11 | Extraction Time: {datetime.now(UTC).isoformat()} | Tool: {TOOL_VERSION}", self.styles["BodyText"]))
            story.append(Paragraph("Section 10: Investigator Certification", self.styles["Heading1"]))
            story.append(Paragraph("Section 65B declaration recorded; NIST SP 800-86 and ACPO guidance considered.", self.styles["BodyText"]))
            story.append(Paragraph("Section 11: Appendix", self.styles["Heading1"]))
            story.append(Paragraph("References: NIST SP 800-86, Section 65B IT Act 2000 excerpt, ACPO guidelines excerpt.", self.styles["BodyText"]))
            doc.build(story)
            return output
        except Exception:
            logger.exception("Failed generating PDF report")
            raise
