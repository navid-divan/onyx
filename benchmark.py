from __future__ import annotations

import json
import platform
import sys
from dataclasses import dataclass
from typing import Dict

from utils import TimingTracker


@dataclass
class BenchmarkReport:
    timings: Dict[str, float]
    platform_information: Dict[str, str]
    metadata: Dict[str, object]

    def to_json(self) -> str:
        return json.dumps(
            {
                "timings_seconds": self.timings,
                "platform": self.platform_information,
                "metadata": self.metadata,
            },
            indent=2,
            sort_keys=True,
        )


def collect_platform_information() -> Dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def build_report(tracker: TimingTracker, metadata: Dict[str, object]) -> BenchmarkReport:
    return BenchmarkReport(
        timings=dict(tracker.timings),
        platform_information=collect_platform_information(),
        metadata=metadata,
    )


def print_section_header(title: str) -> None:
    bar = "=" * 64
    print(bar)
    print(title.center(64))
    print(bar)


def print_phase_timing(label: str, seconds: float) -> None:
    print(f"  [{label:<14}] {seconds:8.4f} s")
