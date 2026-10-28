"""Networks as the window shows them: numbered, and with a color that stays put."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..models import Network
from .theme import SERIES_COUNT

CURRENT_SLOT = 0
"""The connected network always gets the first color, so it matches the signal history line."""


@dataclass(frozen=True)
class Entry:
    index: int
    """Number shown in the table and on the chart, 1 for the strongest."""
    network: Network
    slot: int | None
    """Categorical color slot, or None for networks drawn in neutral gray."""


class SlotAssigner:
    """Hands out the categorical colors for one band.

    Color follows the network rather than its rank: a network keeps its slot for as
    long as it stays in range, so a new or vanished neighbour doesn't repaint the
    rest. Tracking needs BSSIDs; while macOS redacts them, slots are dealt afresh
    each scan, strongest first. Networks beyond the palette stay gray.
    """

    def __init__(self, slots: int = SERIES_COUNT):
        self._count = slots
        self._sticky: dict[str, int] = {}

    def assign(self, networks: Sequence[Network]) -> list[int | None]:
        present = {n.bssid for n in networks if n.bssid and not n.is_current}
        self._sticky = {bssid: s for bssid, s in self._sticky.items() if bssid in present}

        slots: list[int | None] = []
        for n in networks:
            if n.is_current:
                slots.append(CURRENT_SLOT)
            else:
                slots.append(self._sticky.get(n.bssid) if n.bssid else None)

        taken = set(self._sticky.values())
        free = [s for s in range(self._count) if s != CURRENT_SLOT and s not in taken]
        for i in sorted(range(len(networks)), key=lambda i: -networks[i].rssi):
            if slots[i] is None and free:
                slot = free.pop(0)
                slots[i] = slot
                bssid = networks[i].bssid
                if bssid:
                    self._sticky[bssid] = slot
        return slots
