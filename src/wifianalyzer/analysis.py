"""Signal quality, interference estimates and channel recommendations."""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass

from .channels import block_label, candidate_channels, is_dfs, overlap, span
from .models import Band, Connection, Network, ScanResult


def signal_quality(rssi: int) -> int:
    """RSSI as a 0–100 % score, linear between -100 dBm and -50 dBm."""
    return max(0, min(100, 2 * (rssi + 100)))


def signal_label(rssi: int) -> str:
    """A word for how usable a signal is: excellent, good, fair, weak or poor."""
    if rssi >= -50:
        return "excellent"
    if rssi >= -60:
        return "good"
    if rssi >= -70:
        return "fair"
    if rssi >= -80:
        return "weak"
    return "poor"


@dataclass(frozen=True)
class ChannelScore:
    band: Band
    channel: int
    width: int
    networks: int
    """Number of networks overlapping the channel."""
    interference_dbm: float | None
    """Combined power those networks put into the channel; None when it is clear."""
    dfs: bool

    @property
    def interference_mw(self) -> float:
        return 0.0 if self.interference_dbm is None else 10 ** (self.interference_dbm / 10)


def interference_level(score: ChannelScore) -> str:
    """Coarse rating of a channel's interference: clear, low, moderate or high."""
    if score.interference_dbm is None:
        return "clear"
    if score.interference_dbm >= -60:
        return "high"
    if score.interference_dbm >= -75:
        return "moderate"
    return "low"


@dataclass(frozen=True)
class BandReport:
    band: Band
    width: int
    ranked: list[ChannelScore]
    """Candidate channels, least interference first."""
    current: ChannelScore | None
    """Score of the connected channel, when the connection is on this band."""


def score_channel(networks: Iterable[Network], band: Band, channel: int, width: int) -> ChannelScore:
    """Estimate how much energy from ``networks`` lands in a channel.

    Each network's power is assumed to be spread evenly over its width, so a
    neighbour that only partly overlaps contributes that fraction of its signal.
    """
    target = span(band, channel, width)
    total_mw = 0.0
    count = 0
    for n in networks:
        if n.band is not band:
            continue
        shared = overlap(target, span(band, n.channel, n.width))
        if shared <= 0:
            continue
        count += 1
        total_mw += 10 ** (n.rssi / 10) * shared / n.width
    dbm = 10 * math.log10(total_mw) if total_mw else None
    return ChannelScore(band, channel, width, count, dbm, is_dfs(band, channel, width))


def _same_radio(a: Network, b: Network) -> bool:
    """Whether two scan entries look like one radio broadcasting several SSIDs (e.g. a guest network)."""
    return (a.band, a.channel, a.width, a.phy) == (b.band, b.channel, b.width, b.phy) and abs(a.rssi - b.rssi) <= 3


def is_own(network: Network, connection: Connection | None, current: Network | None = None) -> bool:
    """Whether a network belongs to the user's own Wi-Fi rather than a neighbour's.

    ``current`` is the scanned entry of the connected access point, if known.
    """
    if network.is_current:
        return True
    if connection and connection.ssid and network.ssid == connection.ssid:
        return True
    return current is not None and _same_radio(network, current)


def recommend(result: ScanResult, band: Band, width: int | None = None) -> BandReport:
    """Rank channels on ``band`` by how much interference neighbouring networks cause.

    The width defaults to the current connection's width on that band, or 80 MHz
    for 5/6 GHz otherwise. 2.4 GHz is always evaluated at 20 MHz: wider channels
    there overlap most of the band.
    """
    conn = result.connection
    on_band = conn if conn is not None and conn.band is band else None
    if band is Band.GHZ_2_4:
        width = 20
    elif width is None:
        width = on_band.width if on_band else 80
    if band is Band.GHZ_5:
        width = min(width, 160)

    current = next((n for n in result.networks if n.is_current), None)
    neighbours = [n for n in result.networks if n.band is band and not is_own(n, conn, current)]
    ranked = sorted(
        (score_channel(neighbours, band, ch, width) for ch in candidate_channels(band, width)),
        key=lambda s: (s.interference_mw, s.networks, s.dfs),
    )
    current_score = score_channel(neighbours, band, on_band.channel, on_band.width) if on_band else None
    return BandReport(band, width, ranked, current_score)


def verdict(report: BandReport) -> str:
    """One-line advice comparing the connected channel with the best candidate."""
    best, current = report.ranked[0] if report.ranked else None, report.current
    if best is None or current is None:
        return ""
    if span(best.band, best.channel, best.width) == span(current.band, current.channel, current.width):
        return "You're already on the best channel"
    if current.interference_mw == 0:
        return "Your channel is clear, no change needed"
    best_label = block_label(best.band, best.channel, best.width)
    if best.interference_mw == 0:
        return f"Switch to {best_label}: no neighbours overlap it"
    gain = 10 * math.log10(current.interference_mw / best.interference_mw)
    if gain < 3:
        return "Your channel is within 3 dB of the best"
    return f"Switch to {best_label} for ~{gain:.0f} dB less interference"


def bands_in(result: ScanResult) -> list[Band]:
    """Bands with at least one scanned network or the active connection, in band order."""
    seen = {n.band for n in result.networks}
    if result.connection:
        seen.add(result.connection.band)
    return [b for b in Band if b in seen]
