"""Naming, escaping and chart-scale helpers for the desktop app."""

from __future__ import annotations

import math
import sys
import unicodedata
from collections.abc import Iterable

from .models import Band, Network

FLOOR_DBM = -100
"""Bottom of every signal chart; weaker signals are indistinguishable from noise."""

_GENERATIONS = {"802.11n": 4, "802.11ac": 5, "802.11ax": 6, "802.11be": 7}

# Characters that reorder the text around them, which lets a name look like something else.
_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def printable(text: str) -> str:
    """``text`` with control and bidi-override characters spelled out as escapes.

    Network names are chosen by whoever runs the access point. Shown as they are, control
    characters would be invisible, and a bidi override could make one name look like another.
    """
    if text.isprintable():
        return text
    return "".join(
        ch.encode("unicode_escape").decode("ascii") if unicodedata.category(ch) == "Cc" or ch in _BIDI_CONTROLS else ch
        for ch in text
    )


def index_networks(networks: Iterable[Network]) -> list[tuple[int, Network]]:
    """Number networks strongest first; the numbers tie table rows to chart curves."""
    ordered = sorted(networks, key=lambda n: (-n.rssi, n.band.value, n.channel))
    return list(enumerate(ordered, start=1))


def network_name(network: Network) -> str:
    if network.ssid:
        return printable(network.ssid)
    return "—" if network.redacted else "(hidden)"


def connection_name(ssid: str | None) -> str | None:
    """The connected network's name for display, or None when the OS withholds it."""
    return printable(ssid) if ssid else None


def withheld_name() -> str:
    """What to show instead of the connected network's name when there isn't one."""
    return "Name hidden by macOS" if sys.platform == "darwin" else "Name unavailable"


def phy_label(phy: str, band: Band) -> str:
    generation = _GENERATIONS.get(phy)
    if generation is None:
        return phy
    name = f"Wi-Fi {generation}" + ("E" if generation == 6 and band is Band.GHZ_6 else "")
    return f"{name} ({phy.removeprefix('802.11')})"


def chart_ceiling(networks: Iterable[Network]) -> int:
    """Top of a chart's dBm scale: 10 dB of headroom above the strongest signal, in steps of 10."""
    strongest = max((n.rssi for n in networks), default=FLOOR_DBM)
    return max(-50, min(-20, math.ceil(strongest / 10) * 10 + 10))


def curve_dbm(rssi: int, t: float) -> float:
    """Height of a network's spectrum curve at relative position ``t`` (-1 to 1) across its channel.

    1 - t^4 gives a flat top with steep sides, closer to a real spectral mask than a parabola.
    """
    return FLOOR_DBM + max(0, rssi - FLOOR_DBM) * (1 - t**4)
