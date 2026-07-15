"""
Integration example: ProcessBehaviorAnalyzer with Artifact Pulse CorrelationEngine

This shows how to integrate the Heuristic Correlation Engine into your main workflow.
"""

from core.correlation_engine import CorrelationEngine, ProcessBehaviorAnalyzer
from database.db_manager import DBManager
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def integrated_forensic_analysis():
    """
    Complete forensic analysis combining timeline correlation and behavioral anomalies.
    
    Workflow:
    1. Build super timeline from all artifacts
    2. Find suspicious temporal clusters
    3. Analyze process behaviors for anti-forensic indicators
    4. Correlate findings for comprehensive investigation report
    """
    
    try:
        # Initialize database and correlation engine
        db = DBManager()
        timeline_engine = CorrelationEngine(db)
        behavior_analyzer = ProcessBehaviorAnalyzer(contamination=0.10)
        
        print("\n" + "=" * 90)
        print("ARTIFACT PULSE - INTEGRATED FORENSIC ANALYSIS")
        print("=" * 90)
        
        # Phase 1: Timeline Analysis
        print("\n[PHASE 1] Building forensic timeline...")
        timeline_df = timeline_engine.build_super_timeline()
        print(f"  ✓ Timeline built with {len(timeline_df)} events")
        
        # Phase 2: Suspicious Clusters
        print("\n[PHASE 2] Identifying suspicious temporal clusters...")
        clusters = timeline_engine.find_suspicious_clusters(window_minutes=5)
        print(f"  ✓ Found {len(clusters)} suspicious clusters")
        for cluster in clusters[:3]:
            print(f"     - {cluster['attack_type']}: Score {cluster['suspicion_score']}")
        
        # Phase 3: Process Behavior Analysis
        print("\n[PHASE 3] Analyzing process behavior anomalies...")
        
        # Get process data from database or create sample
        processes_query = """
        SELECT 
            pid as PID,
            thread_count as Thread_Count,
            file_io_rate as File_IO_Rate,
            memory_jump as Memory_Jump
        FROM process_snapshot
        """
        
        # For demo, create sample data
        processes_data = pd.DataFrame({
            'PID': range(1000, 1170),
            'Thread_Count': [8] * 150 + [60] * 20,
            'File_IO_Rate': [15] * 150 + [80] * 20,
            'Memory_Jump': [5] * 150 + [120] * 20,
        })
        
        # Analyze behaviors
        behavior_result = behavior_analyzer.analyze(processes_data)
        print(f"  ✓ Process analysis complete")
        print(f"     - Total processes: {behavior_result['total_processes']}")
        print(f"     - Anomalies detected: {behavior_result['anomalies_detected']}")
        print(f"     - Critical risk: {behavior_result['critical_count']}")
        print(f"     - High risk: {behavior_result['high_count']}")
        
        # Phase 4: Anomaly Report
        print("\n[PHASE 4] Generating anomaly report...")
        behavior_analyzer.print_results(include_all=False)
        
        # Phase 5: Correlation Analysis
        print("\n[PHASE 5] Correlating findings...")
        
        anomalous_pids = set(behavior_analyzer.anomalies['PID'].astype(int))
        suspicious_events = timeline_df[
            timeline_df['content'].astype(str).str.contains('|'.join(map(str, anomalous_pids)), na=False)
        ]
        
        print(f"  ✓ Correlation analysis:")
        print(f"     - Anomalous processes: {len(anomalous_pids)}")
        print(f"     - Timeline events linked: {len(suspicious_events)}")
        
        if len(clusters) > 0 and len(anomalous_pids) > 0:
            print(f"     - ⚠ CRITICAL: Temporal clusters + behavioral anomalies detected!")
            print(f"       This suggests coordinated anti-forensic activity.")
        
        # Phase 6: Investigation Summary
        print("\n[PHASE 6] Investigation Summary")
        print("-" * 90)
        
        summary = {
            "Timeline Clusters": len(clusters),
            "Behavioral Anomalies": behavior_result['anomalies_detected'],
            "Critical Risk Processes": behavior_result['critical_count'],
            "Suspicion Level": "CRITICAL" if (len(clusters) > 0 and behavior_result['anomalies_detected'] > 0) else "HIGH"
        }
        
        for key, value in summary.items():
            print(f"  {key:<30} : {value}")
        
        print("=" * 90 + "\n")
        
        return {
            "timeline_clusters": clusters,
            "behavioral_anomalies": behavior_result,
            "correlation_score": (len(clusters) * 0.5 + behavior_result['anomalies_detected'] * 0.5) / 2
        }
        
    except Exception as e:
        logger.exception(f"Integrated analysis failed: {str(e)}")
        raise


def focused_process_analysis(process_snapshot_df):
    """
    Focused analysis on process behaviors only.
    
    Useful for:
    - Real-time process monitoring
    - Incident response on specific machines
    - Endpoint malware detection
    """
    
    analyzer = ProcessBehaviorAnalyzer(contamination=0.05)  # Stricter for focused analysis
    
    print("\n[*] PROCESS BEHAVIOR ANALYSIS")
    print("-" * 60)
    
    # Analyze
    result = analyzer.analyze(process_snapshot_df)
    
    print(f"Total Processes: {result['total_processes']}")
    print(f"Anomalies Found: {result['anomalies_detected']} ({result['anomaly_percentage']:.1f}%)")
    print(f"CRITICAL Risk: {result['critical_count']}")
    print(f"HIGH Risk: {result['high_count']}")
    
    # Print detailed results
    if result['anomalies_detected'] > 0:
        analyzer.print_results(include_all=False)
        
        # Export anomalies for further investigation
        anomalies_export = pd.DataFrame(result['anomalous_processes'])
        print(f"\n[*] Anomaly Export:")
        print(f"    - Columns: {', '.join(anomalies_export.columns.tolist())}")
        print(f"    - Ready for: Database storage, JSON export, Dashboard visualization")
    
    return result


if __name__ == "__main__":
    # Run integrated analysis
    analysis_results = integrated_forensic_analysis()
    
    print("\n[*] Analysis complete. Next steps:")
    print("    1. Review anomalous processes in detail")
    print("    2. Correlate with network logs and file system artifacts")
    print("    3. Generate forensic report")
    print("    4. Archive evidence for legal proceedings")
