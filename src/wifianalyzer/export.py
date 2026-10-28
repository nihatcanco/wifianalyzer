"""Scan results as JSON, for the desktop app's Save Scan."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime

from .analysis import BandReport
from .models import ScanResult


def _encode(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def to_json(result: ScanResult, reports: Sequence[BandReport]) -> str:
    """The scan and its channel recommendations. Non-ASCII characters in names are escaped."""
    data = asdict(result)
    data["recommendations"] = [asdict(r) for r in reports]
    return json.dumps(data, default=_encode, indent=2)
