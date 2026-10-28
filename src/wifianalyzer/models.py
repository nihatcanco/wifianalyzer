"""What a scan produces: the networks in range and the link the computer is connected to."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Band(StrEnum):
    GHZ_2_4 = "2.4"
    GHZ_5 = "5"
    GHZ_6 = "6"

    @property
    def label(self) -> str:
        return f"{self.value} GHz"


@dataclass(frozen=True)
class Network:
    """One BSS seen in a scan.

    ``ssid`` and ``bssid`` are None when the operating system withholds them, which macOS
    does for programs without Location Services permission.
    """

    ssid: str | None
    bssid: str | None
    rssi: int
    noise: int | None
    band: Band
    channel: int
    width: int
    security: str
    phy: str
    beacon_interval: int | None = None
    is_current: bool = False

    @property
    def snr(self) -> int | None:
        return None if self.noise is None else self.rssi - self.noise

    @property
    def redacted(self) -> bool:
        # Access points never hide their BSSID, so a missing one means the OS withheld it.
        return self.bssid is None


@dataclass(frozen=True)
class Connection:
    """The link the Wi-Fi interface is currently associated with."""

    ssid: str | None
    bssid: str | None
    rssi: int
    noise: int | None
    tx_rate: float
    band: Band
    channel: int
    width: int
    security: str
    phy: str

    @property
    def snr(self) -> int | None:
        return None if self.noise is None else self.rssi - self.noise


def _now() -> datetime:
    return datetime.now().astimezone()


@dataclass(frozen=True)
class ScanResult:
    interface: str
    networks: list[Network]
    connection: Connection | None
    country: str | None = None
    timestamp: datetime = field(default_factory=_now)
    """When the scan finished, in local time with its UTC offset."""

    @property
    def redacted(self) -> bool:
        return any(n.redacted for n in self.networks)
