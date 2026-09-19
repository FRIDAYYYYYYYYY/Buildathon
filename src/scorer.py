"""Hybrid risk scoring engine for AegisAI.

Combines deterministic heuristic rule scores and Isolation Forest anomaly scores
into a stateful per-user running risk tally and checks against configured incident thresholds.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from src.anomaly import anomaly_score
from src.config import (
    BURST_BONUS,
    BURST_MIN_EVENTS,
    BURST_THRESHOLD_SCORE,
    BURST_WINDOW_SECONDS,
    THRESHOLD,
)
from src.models import Event, ScoreBreakdown
from src.rules import rule_score


class RiskScorer:
    """Stateful engine that aggregates hybrid telemetry scores and temporal bursts per user."""

    def __init__(
        self,
        threshold: int = THRESHOLD,
        burst_window_seconds: int = BURST_WINDOW_SECONDS,
        burst_threshold_score: int = BURST_THRESHOLD_SCORE,
        burst_min_events: int = BURST_MIN_EVENTS,
        burst_bonus: int = BURST_BONUS,
    ) -> None:
        """Initialize RiskScorer with configurable incident and temporal burst parameters.

        Args:
            threshold: Cumulative point score at which an incident is triggered.
            burst_window_seconds: Sliding window duration in seconds for temporal correlation.
            burst_threshold_score: Minimum (rule + anomaly) score to qualify as a suspicious burst event.
            burst_min_events: Minimum number of qualifying events within window to award burst bonus.
            burst_bonus: Additional risk point bonus added when burst condition is triggered.
        """
        self.threshold: int = threshold
        self.burst_window_seconds: int = burst_window_seconds
        self.burst_threshold_score: int = burst_threshold_score
        self.burst_min_events: int = burst_min_events
        self.burst_bonus: int = burst_bonus
        self._user_scores: dict[str, int] = {}
        self._user_burst_history: dict[str, list[datetime]] = {}

    def get_user_score(self, user: str) -> int:
        """Get the current cumulative risk score for a given user."""
        return self._user_scores.get(user, 0)

    def reset_user(self, user: str) -> None:
        """Reset running score and burst tracking history for a specific user."""
        self._user_scores.pop(user, None)
        self._user_burst_history.pop(user, None)

    def reset_all(self) -> None:
        """Clear all running score tallies and burst histories."""
        self._user_scores.clear()
        self._user_burst_history.clear()

    def score_event(self, event: Event) -> ScoreBreakdown:
        """Compute individual, burst bonus, and cumulative scores for an incoming event.

        Args:
            event: Validated telemetry Event.

        Returns:
            ScoreBreakdown: Full audit breakdown of rules, anomaly, burst bonus, and cumulative risk.
        """
        r_score = rule_score(event)
        a_score = anomaly_score(event)

        # SIEM Best Practice: Noise-floor gating.
        # Purely benign events (rule_score == 0 and anomaly < 30) do not accumulate risk.
        if r_score == 0 and a_score < 30:
            raw_event_risk = 0
        else:
            raw_event_risk = r_score + a_score

        # Temporal Burst Correlation:
        # Track timestamps of suspicious events (raw score > burst_threshold_score) within sliding window.
        burst_points = 0
        raw_combined = r_score + a_score
        if raw_combined > self.burst_threshold_score:
            if event.user not in self._user_burst_history:
                self._user_burst_history[event.user] = []

            self._user_burst_history[event.user].append(event.timestamp)
            cutoff = event.timestamp - timedelta(seconds=self.burst_window_seconds)
            self._user_burst_history[event.user] = [
                ts for ts in self._user_burst_history[event.user] if ts >= cutoff
            ]

            if len(self._user_burst_history[event.user]) >= self.burst_min_events:
                burst_points = self.burst_bonus

        # Burst bonus is genuinely additive to cumulative risk
        effective_event_risk = raw_event_risk + burst_points

        prior_score = self._user_scores.get(event.user, 0)
        cumulative = prior_score + effective_event_risk
        self._user_scores[event.user] = cumulative

        is_breached = cumulative >= self.threshold

        return ScoreBreakdown(
            user=event.user,
            rule_score=r_score,
            anomaly_score=a_score,
            combined_score=raw_event_risk,
            burst_bonus=burst_points,
            cumulative_score=cumulative,
            is_breached=is_breached,
        )


# Global singleton instance for operational pipeline
_DEFAULT_SCORER: RiskScorer | None = None


def get_default_scorer() -> RiskScorer:
    """Retrieve or initialize the default RiskScorer singleton."""
    global _DEFAULT_SCORER
    if _DEFAULT_SCORER is None:
        _DEFAULT_SCORER = RiskScorer()
    return _DEFAULT_SCORER


def process_event(event: Event) -> int:
    """Process an event through the hybrid scoring pipeline.

    Args:
        event: Validated telemetry Event.

    Returns:
        int: Updated cumulative risk score for the user.
    """
    breakdown = get_default_scorer().score_event(event)
    return breakdown.cumulative_score
