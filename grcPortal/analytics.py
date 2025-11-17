"""
Advanced Analytics and Statistical Methods for GRC Portal
Implements data analytics tools and statistical methods for compliance auditing
"""

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class StatisticalAnalyzer:
    """Statistical analysis methods for evidence analysis"""

    @staticmethod
    def calculate_confidence_intervals(data: List[float], confidence: float = 0.95) -> Dict[str, float]:
        """Calculate confidence intervals for a dataset"""
        if len(data) < 2:
            return {"mean": np.mean(data), "lower_bound": np.mean(data), "upper_bound": np.mean(data)}

        mean = np.mean(data)
        std_err = stats.sem(data)
        margin = std_err * stats.t.ppf((1 + confidence) / 2, len(data) - 1)

        return {
            "mean": mean,
            "lower_bound": mean - margin,
            "upper_bound": mean + margin,
            "margin_of_error": margin,
            "confidence_level": confidence
        }

    @staticmethod
    def perform_hypothesis_test(sample1: List[float], sample2: List[float],
                               test_type: str = 't-test') -> Dict[str, Any]:
        """Perform statistical hypothesis testing"""
        if test_type == 't-test':
            t_stat, p_value = stats.ttest_ind(sample1, sample2)
            test_name = "Independent t-test"
        elif test_type == 'mann-whitney':
            t_stat, p_value = stats.mannwhitneyu(sample1, sample2)
            test_name = "Mann-Whitney U test"
        else:
            return {"error": "Unsupported test type"}

        return {
            "test_name": test_name,
            "test_statistic": t_stat,
            "p_value": p_value,
            "significant": p_value < 0.05,
            "alpha": 0.05
        }

    @staticmethod
    def calculate_correlation_matrix(data: pd.DataFrame) -> Dict[str, Any]:
        """Calculate correlation matrix for multivariate analysis"""
        numeric_cols = data.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) < 2:
            return {"error": "Need at least 2 numeric columns for correlation analysis"}

        corr_matrix = data[numeric_cols].corr()

        # Find strongest correlations
        correlations = []
        for i in range(len(corr_matrix.columns)):
            for j in range(i+1, len(corr_matrix.columns)):
                col1, col2 = corr_matrix.columns[i], corr_matrix.columns[j]
                corr_value = corr_matrix.loc[col1, col2]
                correlations.append({
                    "variable1": col1,
                    "variable2": col2,
                    "correlation": corr_value,
                    "strength": "strong" if abs(corr_value) > 0.7 else "moderate" if abs(corr_value) > 0.3 else "weak"
                })

        # Sort by absolute correlation strength
        correlations.sort(key=lambda x: abs(x["correlation"]), reverse=True)

        return {
            "correlation_matrix": corr_matrix.to_dict(),
            "strongest_correlations": correlations[:10],  # Top 10 correlations
            "variables_analyzed": list(numeric_cols)
        }


class PredictiveAnalytics:
    """Predictive analytics for compliance risk forecasting"""

    def __init__(self):
        self.models = {}
        self.scalers = {}

    def train_compliance_prediction_model(self, historical_data: pd.DataFrame,
                                        target_column: str) -> Dict[str, Any]:
        """Train a predictive model for compliance violations"""

        # Prepare features
        feature_cols = [col for col in historical_data.columns if col != target_column]
        X = historical_data[feature_cols]
        y = historical_data[target_column]

        # Handle categorical variables
        X = pd.get_dummies(X, drop_first=True)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)

        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train_scaled, y_train)

        # Make predictions
        y_pred = model.predict(X_test_scaled)

        # Calculate metrics
        metrics = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(y_test, y_pred, average='weighted'),
            "recall": recall_score(y_test, y_pred, average='weighted'),
            "f1_score": f1_score(y_test, y_pred, average='weighted')
        }

        # Store model and scaler
        model_id = f"compliance_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.models[model_id] = model
        self.scalers[model_id] = scaler

        # Feature importance
        feature_importance = dict(zip(X.columns, model.feature_importances_))
        sorted_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)

        return {
            "model_id": model_id,
            "metrics": metrics,
            "feature_importance": sorted_features[:10],  # Top 10 features
            "training_samples": len(X_train),
            "test_samples": len(X_test)
        }

    def predict_compliance_risk(self, model_id: str, new_data: pd.DataFrame) -> Dict[str, Any]:
        """Make predictions using trained model"""

        if model_id not in self.models:
            return {"error": "Model not found"}

        model = self.models[model_id]
        scaler = self.scalers[model_id]

        # Prepare data
        new_data_processed = pd.get_dummies(new_data, drop_first=True)

        # Ensure same columns as training data
        # This is a simplified version - in production, you'd need proper feature alignment

        try:
            new_data_scaled = scaler.transform(new_data_processed)
            predictions = model.predict(new_data_scaled)
            probabilities = model.predict_proba(new_data_scaled)

            return {
                "predictions": predictions.tolist(),
                "probabilities": probabilities.tolist(),
                "prediction_confidence": np.max(probabilities, axis=1).tolist()
            }
        except Exception as e:
            return {"error": f"Prediction failed: {str(e)}"}

    def detect_anomalies(self, data: pd.DataFrame, contamination: float = 0.1) -> Dict[str, Any]:
        """Detect anomalies using isolation forest"""

        # Prepare numeric data
        numeric_data = data.select_dtypes(include=[np.number])

        if numeric_data.empty:
            return {"error": "No numeric data available for anomaly detection"}

        # Train anomaly detection model
        model = IsolationForest(contamination=contamination, random_state=42)
        anomalies = model.fit_predict(numeric_data)

        # Calculate anomaly scores
        scores = model.decision_function(numeric_data)

        # Identify anomalous records
        anomaly_indices = np.where(anomalies == -1)[0]
        normal_indices = np.where(anomalies == 1)[0]

        return {
            "total_records": len(data),
            "anomalies_detected": len(anomaly_indices),
            "normal_records": len(normal_indices),
            "anomaly_percentage": (len(anomaly_indices) / len(data)) * 100,
            "anomaly_scores": scores.tolist(),
            "anomaly_indices": anomaly_indices.tolist()
        }


class ComplianceAnalyticsEngine:
    """Main analytics engine for compliance data"""

    def __init__(self):
        self.statistical_analyzer = StatisticalAnalyzer()
        self.predictive_analytics = PredictiveAnalytics()

    def perform_comprehensive_analysis(self, compliance_data: pd.DataFrame,
                                    analysis_type: str) -> Dict[str, Any]:
        """Perform comprehensive analysis based on type"""

        results = {
            "analysis_type": analysis_type,
            "timestamp": datetime.now().isoformat(),
            "data_summary": {
                "total_records": len(compliance_data),
                "columns": list(compliance_data.columns),
                "data_types": compliance_data.dtypes.to_dict()
            }
        }

        try:
            if analysis_type == "statistical":
                # Basic statistical analysis
                numeric_cols = compliance_data.select_dtypes(include=[np.number]).columns

                for col in numeric_cols:
                    data = compliance_data[col].dropna().tolist()
                    if data:
                        results[col] = {
                            "mean": np.mean(data),
                            "median": np.median(data),
                            "std_dev": np.std(data),
                            "min": np.min(data),
                            "max": np.max(data),
                            "confidence_interval": self.statistical_analyzer.calculate_confidence_intervals(data)
                        }

            elif analysis_type == "correlational":
                # Correlation analysis
                results["correlation_analysis"] = self.statistical_analyzer.calculate_correlation_matrix(compliance_data)

            elif analysis_type == "predictive":
                # Predictive modeling
                if 'compliance_score' in compliance_data.columns:
                    results["predictive_model"] = self.predictive_analytics.train_compliance_prediction_model(
                        compliance_data, 'compliance_score'
                    )

            elif analysis_type == "anomaly_detection":
                # Anomaly detection
                results["anomaly_analysis"] = self.predictive_analytics.detect_anomalies(compliance_data)

            elif analysis_type == "trend_analysis":
                # Time series trend analysis
                if 'date' in compliance_data.columns:
                    compliance_data['date'] = pd.to_datetime(compliance_data['date'])
                    compliance_data = compliance_data.sort_values('date')

                    # Simple trend calculation
                    if 'compliance_score' in compliance_data.columns:
                        scores = compliance_data['compliance_score'].dropna()
                        if len(scores) > 1:
                            trend = np.polyfit(range(len(scores)), scores, 1)[0]
                            results["trend_analysis"] = {
                                "trend_slope": trend,
                                "trend_direction": "improving" if trend > 0 else "declining",
                                "data_points": len(scores)
                            }

            results["status"] = "completed"

        except Exception as e:
            logger.error(f"Analysis failed: {str(e)}")
            results["status"] = "failed"
            results["error"] = str(e)

        return results

    def generate_compliance_insights(self, analysis_results: Dict[str, Any]) -> List[str]:
        """Generate human-readable insights from analysis results"""

        insights = []

        if analysis_results.get("status") != "completed":
            return ["Analysis failed to complete"]

        analysis_type = analysis_results.get("analysis_type", "")

        if analysis_type == "statistical":
            # Generate insights from statistical analysis
            for key, stats in analysis_results.items():
                if isinstance(stats, dict) and "mean" in stats:
                    mean_val = stats["mean"]
                    std_dev = stats.get("std_dev", 0)
                    insights.append(f"{key}: Average value is {mean_val:.2f} with standard deviation of {std_dev:.2f}")

        elif analysis_type == "correlational":
            corr_data = analysis_results.get("correlation_analysis", {})
            strongest = corr_data.get("strongest_correlations", [])

            for corr in strongest[:3]:  # Top 3 correlations
                var1, var2 = corr["variable1"], corr["variable2"]
                strength = corr["correlation"]
                insights.append(f"Strong {corr['strength']} correlation ({strength:.2f}) found between {var1} and {var2}")

        elif analysis_type == "anomaly_detection":
            anomaly_data = analysis_results.get("anomaly_analysis", {})
            total = anomaly_data.get("total_records", 0)
            anomalies = anomaly_data.get("anomalies_detected", 0)

            if total > 0:
                percentage = (anomalies / total) * 100
                insights.append(f"Detected {anomalies} anomalies out of {total} records ({percentage:.1f}%)")

        elif analysis_type == "predictive":
            model_data = analysis_results.get("predictive_model", {})
            metrics = model_data.get("metrics", {})

            accuracy = metrics.get("accuracy", 0)
            if accuracy > 0:
                insights.append(f"Predictive model achieved {accuracy:.1%} accuracy")

            features = model_data.get("feature_importance", [])
            if features:
                top_feature = features[0][0]
                insights.append(f"Most important predictor: {top_feature}")

        return insights if insights else ["No significant insights generated"]


# Global analytics engine instance
analytics_engine = ComplianceAnalyticsEngine()


def perform_evidence_analysis(data: pd.DataFrame, analysis_config: Dict[str, Any]) -> Dict[str, Any]:
    """Main function for performing evidence analysis"""

    analysis_type = analysis_config.get("analysis_type", "statistical")

    # Perform comprehensive analysis
    results = analytics_engine.perform_comprehensive_analysis(data, analysis_type)

    # Generate insights
    insights = analytics_engine.generate_compliance_insights(results)

    results["insights"] = insights
    results["analysis_config"] = analysis_config

    return results


def run_predictive_compliance_model(historical_data: pd.DataFrame,
                                  prediction_target: str) -> Dict[str, Any]:
    """Run predictive modeling for compliance forecasting"""

    return analytics_engine.predictive_analytics.train_compliance_prediction_model(
        historical_data, prediction_target
    )


def generate_automated_report(analytics_results: Dict[str, Any],
                            report_config: Dict[str, Any]) -> str:
    """Generate automated compliance report"""

    report_type = report_config.get("report_type", "compliance_status")

    # Build report content
    report_content = f"""
# Automated {report_type.replace('_', ' ').title()} Report

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

Analysis completed with status: {analytics_results.get('status', 'unknown')}

## Key Findings

"""

    insights = analytics_results.get("insights", [])
    for insight in insights:
        report_content += f"- {insight}\n"

    # Add detailed results
    if "correlation_analysis" in analytics_results:
        report_content += "\n## Correlation Analysis\n"
        corr_data = analytics_results["correlation_analysis"]
        strongest = corr_data.get("strongest_correlations", [])

        for corr in strongest[:5]:  # Top 5 correlations
            report_content += f"- {corr['variable1']} ↔ {corr['variable2']}: {corr['correlation']:.3f} ({corr['strength']})\n"

    if "predictive_model" in analytics_results:
        report_content += "\n## Predictive Model Performance\n"
        model_data = analytics_results["predictive_model"]
        metrics = model_data.get("metrics", {})

        report_content += f"- Accuracy: {metrics.get('accuracy', 0):.1%}\n"
        report_content += f"- Precision: {metrics.get('precision', 0):.1%}\n"
        report_content += f"- Recall: {metrics.get('recall', 0):.1%}\n"

    report_content += "\n## Recommendations\n"
    report_content += "- Review analysis results and implement appropriate controls\n"
    report_content += "- Schedule follow-up analysis based on findings\n"
    report_content += "- Update compliance monitoring thresholds if needed\n"

    return report_content