"""Artifact-Pulse CLI entrypoint and web launcher."""

from __future__ import annotations

import logging

try:
    from colorama import Fore, Style, init
except ImportError:
    class MockColor:
        def __getattr__(self, name: str) -> str:
            return ""
    Fore = MockColor()
    Style = MockColor()
    def init(*args, **kwargs) -> None:
        pass

try:
    from tabulate import tabulate
except ImportError:
    def tabulate(data, headers=None, tablefmt=None) -> str:
        out = []
        if headers:
            out.append(" | ".join(str(h) for h in headers))
            out.append("-" * 40)
        for row in data:
            out.append(" | ".join(str(item) for item in row))
        return "\n".join(out)


from core.antiforensic_detector import AntiForensicDetector
from core.correlation_engine import CorrelationEngine
from core.eventlog_extractor import EventLogExtractor
from core.evidence_sealer import EvidenceSealer
from core.filesystem_extractor import FilesystemExtractor
from core.ml_scorer import MLScorer
from core.process_extractor import ProcessExtractor
from database.db_manager import DBManager
from web.app import app

logger = logging.getLogger(__name__)


def run_cli_pipeline() -> None:
    """Run all core modules sequentially and print structured summary."""
    try:
        init(autoreset=True)
        banner = f"""
{Fore.CYAN}    _         _   _  __            _      ____        _
{Fore.CYAN}   / \  _ __| |_(_)/ _| __ _  ___| |_   |  _ \ _   _| |___  ___
{Fore.CYAN}  / _ \| '__| __| | |_ / _` |/ __| __|  | |_) | | | | / __|/ _ \
{Fore.CYAN} / ___ \ |  | |_| |  _| (_| | (__| |_   |  __/| |_| | \__ \  __/
{Fore.CYAN}/_/   \_\_|   \__|_|_|  \__,_|\___|\__|  |_|    \__,_|_|___/\___|
{Style.RESET_ALL}
"""
        print(banner)
        with DBManager() as db:
            fs = FilesystemExtractor(db).run_all()
            ev = EventLogExtractor(db).run_all()
            pr = ProcessExtractor(db).run_all()
            af = AntiForensicDetector(db).run_all()
            clusters = CorrelationEngine(db).run_all()
            ml = MLScorer(db, clusters).run_all()
            seal = EvidenceSealer(db).seal()
            summary = [
                ["Filesystem artifacts", sum(fs.values()) if fs else 0],
                ["Event/registry artifacts", sum(ev.values()) if ev else 0],
                ["Process artifacts", sum(pr.values()) if pr else 0],
                ["Anti-forensic findings", len(af)],
                ["Suspicious clusters", len(clusters)],
                ["Final severity", ml.get("severity", "LOW")],
                ["Chain integrity", "INTACT" if seal.get("chain_integrity") else "TAMPERED"],
            ]
            print(tabulate(summary, headers=["Metric", "Value"], tablefmt="github"))
    except Exception:
        logger.exception("CLI pipeline execution failed")
        raise


if __name__ == "__main__":
    run_cli_pipeline()
    app.run(debug=False, host="127.0.0.1", port=5000)
