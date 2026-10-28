"""Channel and frequency math for the 2.4, 5 and 6 GHz bands."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Band, Network

CHANNELS: dict[Band, list[int]] = {
    Band.GHZ_2_4: list(range(1, 14)),
    Band.GHZ_5: [*range(36, 65, 4), *range(100, 145, 4), *range(149, 178, 4)],
    Band.GHZ_6: list(range(1, 234, 4)),
}

# Center channels of the fixed 5 GHz bonding blocks for each channel width.
_BONDED_5GHZ: dict[int, list[int]] = {
    40: [38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175],
    80: [42, 58, 106, 122, 138, 155, 171],
    160: [50, 114, 163],
}

# Channels above 165 (U-NII-4) are allowed in few countries, so they are never recommended.
_HIGHEST_5GHZ_CHANNEL = 165

# Frequency ranges (MHz) to plot. 5 GHz has unused gaps between its sub-bands,
# so it is drawn as separate segments.
SEGMENTS: dict[Band, list[tuple[int, int]]] = {
    Band.GHZ_2_4: [(2401, 2483)],
    Band.GHZ_5: [(5170, 5330), (5490, 5730), (5735, 5835)],
    Band.GHZ_6: [(5945, 7125)],
}

# 5 GHz channels 52–144 (U-NII-2A/2C) need radar detection, so APs may have to vacate them.
DFS_RANGE = (5250.0, 5730.0)


def channel_frequency(band: Band, channel: int) -> int:
    """Center frequency in MHz of a 20 MHz channel."""
    if band is Band.GHZ_2_4:
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band is Band.GHZ_5:
        return 5000 + 5 * channel
    # Channel 2 sits below channel 1, at the bottom edge of the band.
    return 5935 if channel == 2 else 5950 + 5 * channel


def from_frequency(mhz: int) -> tuple[Band, int] | None:
    """Band and channel number of a 20 MHz channel's center frequency.

    Returns None for frequencies outside the 2.4, 5 and 6 GHz Wi-Fi channels, such as
    Japan's 4.9 GHz band or 60 GHz.
    """
    if mhz == 2484:
        return Band.GHZ_2_4, 14
    if 2412 <= mhz <= 2472:
        return Band.GHZ_2_4, (mhz - 2407) // 5
    if 5160 <= mhz <= 5885:
        return Band.GHZ_5, (mhz - 5000) // 5
    if mhz == 5935:
        return Band.GHZ_6, 2
    if 5955 <= mhz <= 7115:
        return Band.GHZ_6, (mhz - 5950) // 5
    return None


def bonded_center(band: Band, channel: int, width: int) -> int:
    """Center channel number of the block a primary channel occupies at ``width`` MHz."""
    if width <= 20:
        return channel
    if band is Band.GHZ_2_4:
        # 40 MHz bonds the primary with the channel 4 above or below it. Scans don't
        # say which, so assume the usual choice: above for low channels, below for high.
        return channel + 2 if channel <= 7 else channel - 2
    if band is Band.GHZ_5:
        half = width // 10
        for center in _BONDED_5GHZ.get(width, []):
            if abs(channel - center) < half:
                return center
        return channel
    block = 4 * (width // 20)
    return (channel - 1) // block * block + block // 2 - 1


def span(band: Band, channel: int, width: int) -> tuple[float, float]:
    """Frequency range in MHz occupied by a transmission."""
    center = channel_frequency(band, bonded_center(band, channel, width))
    return center - width / 2, center + width / 2


def overlap(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Width in MHz shared by two frequency ranges."""
    return max(0.0, min(a[1], b[1]) - max(a[0], b[0]))


def is_dfs(band: Band, channel: int, width: int = 20) -> bool:
    """Whether a transmission overlaps 5 GHz channels that must give way to radar."""
    return band is Band.GHZ_5 and overlap(span(band, channel, width), DFS_RANGE) > 0


def plot_segments(band: Band, networks: Iterable[Network]) -> list[tuple[float, float]]:
    """The band's plot range, widened to fit networks on uncommon edge channels."""
    segments: list[tuple[float, float]] = list(SEGMENTS[band])
    spans = [span(band, n.channel, n.width) for n in networks]
    if spans:
        segments[0] = (min(segments[0][0], *(lo for lo, _ in spans)), segments[0][1])
        segments[-1] = (segments[-1][0], max(segments[-1][1], *(hi for _, hi in spans)))
    return segments


def block_label(band: Band, channel: int, width: int) -> str:
    """Human-readable channel, e.g. ``"36"`` or ``"36–48"`` for 36 at 80 MHz."""
    if width <= 20 or band is Band.GHZ_2_4:
        return str(channel)
    lo, hi = span(band, channel, width)
    covered = [c for c in CHANNELS[band] if lo < channel_frequency(band, c) < hi]
    if not covered:
        return str(channel)
    return f"{covered[0]}–{covered[-1]}"


def candidate_channels(band: Band, width: int) -> list[int]:
    """Primary channels worth evaluating when choosing a channel ``width`` MHz wide."""
    if band is Band.GHZ_2_4:
        # The only 20 MHz channels that don't overlap each other in every region.
        return [1, 6, 11]
    if band is Band.GHZ_5:
        if width <= 20:
            return [c for c in CHANNELS[band] if c <= _HIGHEST_5GHZ_CHANNEL]
        reach = width // 10 - 2  # distance from a block's center to its outermost channel
        return [center - reach for center in _BONDED_5GHZ.get(width, []) if center + reach <= _HIGHEST_5GHZ_CHANNEL]
    block = 4 * (width // 20)
    return list(range(1, 238 - block, block))
