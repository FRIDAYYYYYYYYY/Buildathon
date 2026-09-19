"""Data contracts and validation schemas for AegisAI.

Defines Pydantic models for incoming telemetry events and structured
incident triage outputs, enforcing strict schema and type boundaries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Event(BaseModel):
    """Telemetry event model representing host and user activity snapshots."""

    user: str = Field(..., min_length=1, description="Username or service principal")
    files_touched_per_min: int = Field(
        ..., ge=0, description="Number of file operations within a 1-minute window"
    )
    new_country: bool = Field(
        ..., description="True if authentication or activity originates from a new geolocation"
    )
    process_chain: str = Field(
        ..., min_length=1, description="Observed process parent-child execution sequence"
    )
    cpu_percent: float = Field(
        ..., ge=0.0, le=100.0, description="Host CPU utilization percentage [0-100]"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event occurrence timestamp in UTC",
    )

    @field_validator("user", "process_chain")
    @classmethod
    def strip_whitespace(cls, value: str) -> str:
        """Strip surrounding whitespace from string fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field cannot be empty or whitespace only.")
        return stripped


class TriageResult(BaseModel):
    """Structured LLM triage report output schema."""

    threat_type: str = Field(
        ..., min_length=2, description="Classified threat category (e.g., Ransomware, Exfiltration, Credential Theft)"
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        ..., description="Standardized severity rating"
    )
    plain_summary: str = Field(
        ..., min_length=10, description="Clear, plain-English summary of the suspicious activity and root cause"
    )
    mitigation_command: str = Field(
        ..., min_length=3, description="Concrete containment command (e.g., netsh, pkill, firewall rule)"
    )

    @field_validator("plain_summary", "mitigation_command")
    @classmethod
    def sanitize_strings(cls, value: str) -> str:
        """Sanitize text fields by stripping extraneous whitespace."""
        return value.strip()


class ScoreBreakdown(BaseModel):
    """Container for intermediate rule and anomaly detection score components."""

    user: str
    rule_score: int = Field(..., ge=0, description="Score contributed by deterministic rules engine")
    anomaly_score: int = Field(..., ge=0, le=100, description="Score contributed by Isolation Forest (0-100)")
    combined_score: int = Field(..., ge=0, description="Composite score for the event")
    burst_bonus: int = Field(default=0, ge=0, description="Bonus risk points added when temporal event clustering is detected")
    cumulative_score: int = Field(..., ge=0, description="User's cumulative running risk score")
    is_breached: bool = Field(..., description="Whether cumulative risk exceeded threshold")
