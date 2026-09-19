"""Configuration module for AegisAI.

Loads runtime settings and API credentials from environment variables / .env file.
Ensures zero hardcoded secrets in source code.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Explicitly load .env from project root
BASE_DIR = Path(__file__).resolve().parent.parent
ENV_PATH = BASE_DIR / ".env"
load_dotenv(dotenv_path=ENV_PATH)

# Tunable risk threshold for triggering LLM triage and automated mitigation simulation
# Scores exceeding this threshold escalate to incident status.
DEFAULT_THRESHOLD: int = 75
THRESHOLD: int = int(os.getenv("THRESHOLD", str(DEFAULT_THRESHOLD)))

# Tunable temporal burst correlation constants
DEFAULT_BURST_WINDOW_SECONDS: int = 300  # 5-minute sliding window
BURST_WINDOW_SECONDS: int = int(os.getenv("BURST_WINDOW_SECONDS", str(DEFAULT_BURST_WINDOW_SECONDS)))

DEFAULT_BURST_THRESHOLD_SCORE: int = 30  # Minimum (rule_score + anomaly_score) to qualify for burst tracking
BURST_THRESHOLD_SCORE: int = int(os.getenv("BURST_THRESHOLD_SCORE", str(DEFAULT_BURST_THRESHOLD_SCORE)))

DEFAULT_BURST_MIN_EVENTS: int = 3  # Number of qualifying events within window to trigger burst bonus
BURST_MIN_EVENTS: int = int(os.getenv("BURST_MIN_EVENTS", str(DEFAULT_BURST_MIN_EVENTS)))

DEFAULT_BURST_BONUS: int = 20  # Risk point bonus added when burst condition is met
BURST_BONUS: int = int(os.getenv("BURST_BONUS", str(DEFAULT_BURST_BONUS)))

# Gemini API configuration
GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "").strip()
MODEL_NAME: str = os.getenv("MODEL_NAME", "gemini-2.5-flash").strip()

# Operational settings
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").strip()


def validate_gemini_config() -> bool:
    """Verify whether a valid Gemini API key is configured.

    Returns:
        bool: True if GEMINI_API_KEY is non-empty, False otherwise.
    """
    return bool(GEMINI_API_KEY and GEMINI_API_KEY != "your_gemini_api_key_here")
