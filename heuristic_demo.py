#!/usr/bin/env python3
"""
Heuristic Correlation Engine Demo - Process Behavior Anomaly Detection

This script demonstrates the ProcessBehaviorAnalyzer from the Artifact Pulse
forensic framework. It uses Isolation Forest to detect anti-forensic activity
patterns in process behavior data.

Features:
- Analyzes Process Behaviors (PID, Thread Count, File IO Rate, Memory Jump)
- Detects outliers indicating anti-forensic activity
- Optimized for endpoint forensic tools (efficient, fast)

Usage:
    python heuristic_demo.py
"""

import numpy as np
import pandas as pd
from core.correlation_engine import ProcessBehaviorAnalyzer


def generate_sample_process_data(n_normal: int = 150, n_suspicious: int = 20) -> pd.DataFrame:
    """
    Generate realistic process behavior data for demonstration.
    
    Args:
        n_normal: Number of normal processes
        n_suspicious: Number of suspicious/anomalous processes
        
    Returns:
        DataFrame with process behavior features
    """
    np.random.seed(42)
    
    # Normal process behaviors (legitimate system processes)
    normal_data = {
        "PID": np.random.randint(1000, 10000, n_normal),
        "Thread_Count": np.random.normal(loc=8, scale=3, size=n_normal).clip(1, 100),
        "File_IO_Rate": np.random.normal(loc=15, scale=5, size=n_normal).clip(0, 100),
        "Memory_Jump": np.random.normal(loc=5, scale=2, size=n_normal).clip(0, 50),
    }
    
    # Anomalous process behaviors (potential anti-forensic activity)
    # These exhibit unusual patterns: high thread counts, extreme I/O rates, sudden memory jumps
    suspicious_data = {
        "PID": np.random.randint(10000, 20000, n_suspicious),
        "Thread_Count": np.random.normal(loc=50, scale=20, size=n_suspicious).clip(20, 200),  # Unusually high
        "File_IO_Rate": np.random.normal(loc=80, scale=15, size=n_suspicious).clip(50, 200),  # High I/O
        "Memory_Jump": np.random.normal(loc=100, scale=30, size=n_suspicious).clip(40, 300),  # Extreme jumps
    }
    
    # Combine and shuffle
    df_normal = pd.DataFrame(normal_data)
    df_suspicious = pd.DataFrame(suspicious_data)
    df = pd.concat([df_normal, df_suspicious], ignore_index=True)
    df = df.sample(frac=1).reset_index(drop=True)
    
    return df


def main():
    """Main demonstration of ProcessBehaviorAnalyzer."""
    
    print("\n" + "=" * 90)
    print("ARTIFACT PULSE - HEURISTIC CORRELATION ENGINE DEMO")
    print("Process Behavior Anomaly Detection using Isolation Forest")
    print("=" * 90)
    
    # Generate sample process behavior data
    print("\n[*] Generating sample process behavior dataset...")
    process_data = generate_sample_process_data(n_normal=150, n_suspicious=20)
    print(f"    ✓ Generated {len(process_data)} process records")
    print(f"    Features: PID, Thread_Count, File_IO_Rate, Memory_Jump\n")
    
    # Display sample data
    print("[*] Sample of process data (first 5 records):")
    print(process_data.head().to_string(index=False))
    print()
    
    # Initialize analyzer with contamination = 10% (expect ~10% anomalies)
    print("[*] Initializing ProcessBehaviorAnalyzer (contamination=10%)...")
    analyzer = ProcessBehaviorAnalyzer(contamination=0.10, random_state=42)
    print("    ✓ Analyzer ready\n")
    
    # Run complete analysis pipeline
    print("[*] Running analysis pipeline...")
    print("    - Training Isolation Forest model...")
    print("    - Detecting anomalies...")
    
    # Perform analysis
    analysis_result = analyzer.analyze(process_data)
    
    # Print results
    print("\n[*] Analysis Results:")
    print(f"    Total Processes Analyzed:     {analysis_result['total_processes']}")
    print(f"    Valid Processes (no missing): {analysis_result['valid_processes']}")
    print(f"    Anomalies Detected:           {analysis_result['anomalies_detected']}")
    print(f"    Anomaly Rate:                 {analysis_result['anomaly_percentage']:.2f}%")
    print(f"    ├─ CRITICAL Risk:             {analysis_result['critical_count']}")
    print(f"    └─ HIGH Risk:                 {analysis_result['high_count']}\n")
    
    # Print detailed anomaly report
    analyzer.print_results(include_all=False)
    
    # Additional statistics
    if not analyzer.anomalies.empty:
        print("[*] Anomaly Statistics:")
        print(f"    Avg Thread Count (anomalies):     {analyzer.anomalies['Thread_Count'].mean():.2f}")
        print(f"    Avg File I/O Rate (anomalies):    {analyzer.anomalies['File_IO_Rate'].mean():.2f} ops/s")
        print(f"    Avg Memory Jump (anomalies):      {analyzer.anomalies['Memory_Jump'].mean():.2f} MB\n")
        
        print(f"    Avg Thread Count (all):           {process_data['Thread_Count'].mean():.2f}")
        print(f"    Avg File I/O Rate (all):          {process_data['File_IO_Rate'].mean():.2f} ops/s")
        print(f"    Avg Memory Jump (all):            {process_data['Memory_Jump'].mean():.2f} MB\n")
    
    # Demonstration of detecting anomalies in new data
    print("[*] Testing on new process data...")
    new_data = generate_sample_process_data(n_normal=50, n_suspicious=5)
    new_anomalies = analyzer.detect_anomalies(new_data)
    print(f"    ✓ Detected {len(new_anomalies)} anomalies in new dataset\n")
    
    print("=" * 90)
    print("DEMO COMPLETE - ProcessBehaviorAnalyzer ready for integration")
    print("=" * 90 + "\n")


if __name__ == "__main__":
    main()
