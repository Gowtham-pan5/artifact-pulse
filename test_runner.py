#!/usr/bin/env python
"""Continuous test runner - watches for changes and reruns tests."""
import subprocess
import sys
import time
from pathlib import Path

def run_tests():
    """Run pytest tests."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "--color=yes"],
        cwd=str(Path(__file__).parent)
    )
    return result.returncode

if __name__ == "__main__":
    print("[TEST RUNNER] Starting continuous test mode...")
    print("[TEST RUNNER] Running tests now...\n")
    while True:
        try:
            run_tests()
            print("\n[TEST RUNNER] Waiting for file changes... (or press Ctrl+C to exit)\n")
            time.sleep(2)
        except KeyboardInterrupt:
            print("\n[TEST RUNNER] Stopped")
            sys.exit(0)
