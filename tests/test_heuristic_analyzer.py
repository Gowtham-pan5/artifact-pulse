"""
Test suite for ProcessBehaviorAnalyzer - Heuristic Correlation Engine
Tests the Isolation Forest-based anomaly detection for process behaviors.
"""

import numpy as np
import pandas as pd
import pytest
from core.correlation_engine import ProcessBehaviorAnalyzer


class TestProcessBehaviorAnalyzer:
    """Test ProcessBehaviorAnalyzer functionality."""
    
    @pytest.fixture
    def sample_data(self):
        """Generate sample process behavior data."""
        np.random.seed(42)
        n_normal = 100
        n_anomalies = 20
        
        normal_data = {
            "PID": np.random.randint(1000, 10000, n_normal),
            "Thread_Count": np.random.normal(8, 3, n_normal).clip(1, 50),
            "File_IO_Rate": np.random.normal(15, 5, n_normal).clip(0, 50),
            "Memory_Jump": np.random.normal(5, 2, n_normal).clip(0, 20),
        }
        
        anomaly_data = {
            "PID": np.random.randint(10000, 20000, n_anomalies),
            "Thread_Count": np.random.normal(60, 20, n_anomalies).clip(30, 150),
            "File_IO_Rate": np.random.normal(80, 15, n_anomalies).clip(50, 150),
            "Memory_Jump": np.random.normal(120, 30, n_anomalies).clip(50, 250),
        }
        
        df_normal = pd.DataFrame(normal_data)
        df_anomalies = pd.DataFrame(anomaly_data)
        return pd.concat([df_normal, df_anomalies], ignore_index=True)
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization with default parameters."""
        analyzer = ProcessBehaviorAnalyzer()
        assert analyzer.contamination == 0.1
        assert analyzer.random_state == 42
        assert analyzer.model is None
        assert analyzer.scaler is None
    
    def test_analyzer_custom_contamination(self):
        """Test analyzer initialization with custom contamination."""
        analyzer = ProcessBehaviorAnalyzer(contamination=0.05)
        assert analyzer.contamination == 0.05
    
    def test_fit_model(self, sample_data):
        """Test model fitting."""
        analyzer = ProcessBehaviorAnalyzer()
        analyzer.fit(sample_data)
        assert analyzer.model is not None
        assert analyzer.scaler is not None
    
    def test_detect_anomalies(self, sample_data):
        """Test anomaly detection."""
        analyzer = ProcessBehaviorAnalyzer()
        analyzer.fit(sample_data)
        anomalies = analyzer.detect_anomalies(sample_data)
        
        assert not anomalies.empty
        assert "Prediction" in anomalies.columns
        assert "Anomaly_Score" in anomalies.columns
        assert "Risk_Level" in anomalies.columns
        assert len(anomalies) > 0
    
    def test_analyze_pipeline(self, sample_data):
        """Test complete analyze pipeline."""
        analyzer = ProcessBehaviorAnalyzer()
        result = analyzer.analyze(sample_data)
        
        assert result["total_processes"] == len(sample_data)
        assert result["anomalies_detected"] > 0
        assert "anomalous_processes" in result
    
    def test_risk_level_classification(self):
        """Test risk level classification."""
        assert ProcessBehaviorAnalyzer._risk_level(-0.6) == "CRITICAL"
        assert ProcessBehaviorAnalyzer._risk_level(-0.3) == "HIGH"
        assert ProcessBehaviorAnalyzer._risk_level(-0.1) == "MEDIUM"
        assert ProcessBehaviorAnalyzer._risk_level(0.1) == "LOW"
    
    def test_missing_features(self):
        """Test behavior with missing required features."""
        analyzer = ProcessBehaviorAnalyzer()
        incomplete_data = pd.DataFrame({
            "PID": [1000, 2000],
            "Thread_Count": [5, 10]
            # Missing File_IO_Rate and Memory_Jump
        })
        
        with pytest.raises(ValueError):
            analyzer.fit(incomplete_data)
    
    def test_empty_data(self):
        """Test behavior with empty data."""
        analyzer = ProcessBehaviorAnalyzer()
        empty_data = pd.DataFrame()
        analyzer.fit(empty_data)
        assert analyzer.model is None
    
    def test_detect_without_fit(self):
        """Test anomaly detection without fitting first."""
        analyzer = ProcessBehaviorAnalyzer()
        sample_data = pd.DataFrame({
            "PID": [1000],
            "Thread_Count": [5],
            "File_IO_Rate": [10],
            "Memory_Jump": [2]
        })
        result = analyzer.detect_anomalies(sample_data)
        assert result.empty


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
