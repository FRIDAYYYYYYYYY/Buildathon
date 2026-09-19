"""Anomaly detection module for AegisAI.

Uses an Isolation Forest model trained on baseline telemetry to score statistical
deviations and unknown behavioral anomalies on a normalized 0-100 integer scale.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np
from sklearn.ensemble import IsolationForest

from src.models import Event


class AnomalyDetector:
    """Unsupervised Isolation Forest anomaly detector for host and telemetry events."""

    def __init__(self, contamination: float = 0.05, random_state: int = 42) -> None:
        """Initialize the Isolation Forest detector.

        Args:
            contamination: Expected proportion of outliers in baseline data.
            random_state: Seed for reproducible isolation tree partitions.
        """
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self.is_fitted: bool = False
        self._known_processes: set[str] = set()
        self._mean_files: float = 15.0
        self._std_files: float = 10.0
        self._mean_cpu: float = 15.0
        self._std_cpu: float = 10.0

    def _extract_features(self, event: Event) -> list[float]:
        """Convert an Event into numerical feature vectors.

        Features:
        1. log-scaled files_touched_per_min
        2. normalized cpu_percent
        3. new_country binary flag
        4. process_chain execution depth
        5. process_chain string length
        6. is_novel_process (1.0 if process was never seen in benign training baseline)

        Args:
            event: Validated Event instance.

        Returns:
            List[float]: Extracted numeric feature vector.
        """
        chain = event.process_chain
        depth = float(chain.count("->") + 1)
        length = float(len(chain))
        is_novel = 0.0 if chain in self._known_processes else 1.0

        return [
            math.log1p(float(event.files_touched_per_min)),
            float(event.cpu_percent) / 100.0,
            1.0 if event.new_country else 0.0,
            depth,
            length,
            is_novel,
        ]

    def fit(self, baseline_events: Sequence[Event]) -> None:
        """Train the Isolation Forest and register benign vocabulary.

        Args:
            baseline_events: Sequence of known-benign Event objects.
        """
        if not baseline_events:
            raise ValueError("Cannot fit AnomalyDetector on empty baseline dataset.")

        self._known_processes = {e.process_chain for e in baseline_events}
        files = [float(e.files_touched_per_min) for e in baseline_events]
        cpus = [float(e.cpu_percent) for e in baseline_events]
        self._mean_files = float(np.mean(files))
        self._std_files = max(1.0, float(np.std(files)))
        self._mean_cpu = float(np.mean(cpus))
        self._std_cpu = max(1.0, float(np.std(cpus)))

        X = np.array([self._extract_features(e) for e in baseline_events])
        self.model.fit(X)
        self.is_fitted = True

    def anomaly_score(self, event: Event) -> int:
        """Calculate a normalized anomaly score (0 - 100) for an event.

        Combines Isolation Forest tree isolation depth with multivariate statistical
        z-score deviations to accurately flag both structural and volumetric anomalies.

        Args:
            event: Event to evaluate.

        Returns:
            int: Anomaly score scaled from 0 (benign) to 100 (severe anomaly).
        """
        if not self.is_fitted:
            raise RuntimeError("AnomalyDetector must be fitted before scoring events.")

        X = np.array([self._extract_features(event)])
        # raw decision function: positive for inliers (~0.1 to 0.25), negative for outliers (~ -0.1 to -0.3)
        raw_dec = float(self.model.decision_function(X)[0])

        # Feature z-scores
        z_files = max(0.0, (event.files_touched_per_min - self._mean_files) / self._std_files)
        z_cpu = max(0.0, (event.cpu_percent - self._mean_cpu) / self._std_cpu)

        # Baseline anomaly contribution
        if raw_dec >= 0.08:
            base_score = 5.0
        elif raw_dec >= 0.0:
            base_score = 15.0
        else:
            # Outlier region from isolation trees
            base_score = 30.0 + min(40.0, abs(raw_dec) * 150.0)

        # Statistical variance contribution
        stat_boost = min(30.0, (z_files * 4.0) + (z_cpu * 2.0))
        if event.new_country:
            stat_boost += 15.0
        if event.process_chain not in self._known_processes:
            stat_boost += 15.0

        total = float(np.clip(base_score + stat_boost, 0.0, 100.0))
        return round(total)


# Default module-level singleton instance
_DEFAULT_DETECTOR: AnomalyDetector | None = None


def get_default_detector() -> AnomalyDetector:
    """Retrieve or initialize the lazily trained default AnomalyDetector."""
    global _DEFAULT_DETECTOR
    if _DEFAULT_DETECTOR is None:
        from src.data_generator import generate_baseline_events

        detector = AnomalyDetector()
        baseline = generate_baseline_events(count=500)
        detector.fit(baseline)
        _DEFAULT_DETECTOR = detector
    return _DEFAULT_DETECTOR


def anomaly_score(event: Event) -> int:
    """Compute anomaly score for an event using the default trained detector.

    Args:
        event: Telemetry event.

    Returns:
        int: Normalized 0-100 anomaly score.
    """
    return get_default_detector().anomaly_score(event)
