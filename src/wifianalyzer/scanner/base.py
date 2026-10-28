"""What every scanning backend provides, and the helpers they share."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterable
from dataclasses import replace
from types import TracebackType
from typing import Self

from ..models import Connection, Network, ScanResult


class ScanError(RuntimeError):
    """Scanning failed. The message is written for the user."""


class AccessDeniedError(ScanError):
    """The operating system won't share Wi-Fi details until the user allows it in its settings."""


class Scanner(ABC):
    """One Wi-Fi interface, ready to scan.

    The desktop app calls ``scan`` and ``connection`` from a single worker thread, one call at a
    time, and may call ``cancel`` from another thread to cut a scan short when it quits.
    """

    name: str
    """The interface's name as the operating system shows it, e.g. ``en0``, ``wlan0`` or ``Wi-Fi``."""

    @abstractmethod
    def scan(self) -> ScanResult:
        """Look for networks. Takes a few seconds while the radio visits every channel."""

    @abstractmethod
    def connection(self) -> Connection | None:
        """The current link, or None when disconnected. Cheap enough to call every second."""

    def cancel(self) -> None:  # noqa: B027
        """Stop waiting for a scan in progress. Safe to call from any thread."""

    def close(self) -> None:  # noqa: B027
        """Release the interface. The scanner can't be used afterwards."""

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()


def mark_current(networks: list[Network], connection: Connection | None) -> list[Network]:
    """Flag the scanned entry of the access point the interface is connected to.

    Without BSSIDs (macOS redacts them unless Location access is granted) this falls back to
    the network on the connected channel with the closest RSSI.
    """
    if connection is None:
        return networks
    if connection.bssid:
        match = next((n for n in networks if n.bssid == connection.bssid), None)
    else:
        same_channel = [
            n
            for n in networks
            if (n.band, n.channel, n.width) == (connection.band, connection.channel, connection.width)
        ]
        match = min(same_channel, key=lambda n: abs(n.rssi - connection.rssi), default=None)
    return [replace(n, is_current=True) if n is match else n for n in networks]


def common_country(countries: Iterable[str | None], preferred: str | None = None) -> str | None:
    """The country nearby access points agree on: ``preferred`` if known, else the most common."""
    if preferred:
        return preferred
    counts = Counter(c for c in countries if c)
    return counts.most_common(1)[0][0] if counts else None


def format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)
