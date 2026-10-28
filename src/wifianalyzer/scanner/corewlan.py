"""Scanning on macOS through CoreWLAN."""

from __future__ import annotations

from collections.abc import Callable, Collection
from contextlib import AbstractContextManager
from enum import IntEnum
from typing import Any

from ..models import Band, Connection, Network, ScanResult
from .base import ScanError, Scanner, mark_current


class Security(IntEnum):
    """Mirror of CoreWLAN's CWSecurity."""

    NONE = 0
    WEP = 1
    WPA_PERSONAL = 2
    WPA_PERSONAL_MIXED = 3
    WPA2_PERSONAL = 4
    PERSONAL = 5
    DYNAMIC_WEP = 6
    WPA_ENTERPRISE = 7
    WPA_ENTERPRISE_MIXED = 8
    WPA2_ENTERPRISE = 9
    ENTERPRISE = 10
    WPA3_PERSONAL = 11
    WPA3_ENTERPRISE = 12
    WPA3_TRANSITION = 13
    OWE = 14
    OWE_TRANSITION = 15


SECURITY_NAMES = {
    Security.NONE: "Open",
    Security.WEP: "WEP",
    Security.WPA_PERSONAL: "WPA",
    Security.WPA_PERSONAL_MIXED: "WPA/WPA2",
    Security.WPA2_PERSONAL: "WPA2",
    Security.PERSONAL: "Personal",
    Security.DYNAMIC_WEP: "Dynamic WEP",
    Security.WPA_ENTERPRISE: "WPA Enterprise",
    Security.WPA_ENTERPRISE_MIXED: "WPA/WPA2 Enterprise",
    Security.WPA2_ENTERPRISE: "WPA2 Enterprise",
    Security.ENTERPRISE: "Enterprise",
    Security.WPA3_PERSONAL: "WPA3",
    Security.WPA3_ENTERPRISE: "WPA3 Enterprise",
    Security.WPA3_TRANSITION: "WPA2/WPA3",
    Security.OWE: "OWE",
    Security.OWE_TRANSITION: "OWE Transition",
}

# CWChannelBand, CWChannelWidth and CWPHYMode values.
_BANDS = {1: Band.GHZ_2_4, 2: Band.GHZ_5, 3: Band.GHZ_6}
_WIDTHS = {1: 20, 2: 40, 3: 80, 4: 160}
PHY_MODES = {
    1: "802.11a",
    2: "802.11b",
    3: "802.11g",
    4: "802.11n",
    5: "802.11ac",
    6: "802.11ax",
    7: "802.11be",
}


def security_from_flags(flags: Collection[int]) -> str:
    """Name the security of a scanned network from the modes CoreWLAN says it supports.

    CoreWLAN also reports WPA/WPA2 mixed, generic Personal and WPA3 transition as
    supported by plain WPA2 networks, so only the distinguishing modes are used.
    """
    s = Security
    if s.WPA3_ENTERPRISE in flags:
        return "WPA3 Enterprise"
    if s.WPA2_ENTERPRISE in flags:
        return "WPA2 Enterprise"
    if s.WPA_ENTERPRISE in flags:
        return "WPA Enterprise"
    if s.WPA3_PERSONAL in flags:
        return "WPA2/WPA3" if s.WPA2_PERSONAL in flags else "WPA3"
    if s.WPA2_PERSONAL in flags:
        return "WPA/WPA2" if s.WPA_PERSONAL in flags else "WPA2"
    if s.WPA_PERSONAL in flags:
        return "WPA"
    if s.OWE in flags:
        return "OWE"
    if s.DYNAMIC_WEP in flags:
        return "Dynamic WEP"
    if s.WEP in flags:
        return "WEP"
    if s.NONE in flags:
        return "Open"
    return "Unknown"


def _band(cw_channel: Any) -> Band:
    band = _BANDS.get(cw_channel.channelBand())
    if band is None:
        band = Band.GHZ_2_4 if cw_channel.channelNumber() <= 14 else Band.GHZ_5
    return band


def _phy(supports: Callable[[int], bool]) -> str:
    # Scanned networks only report their newest standard as supported.
    for mode in sorted(PHY_MODES, reverse=True):
        if supports(mode):
            return PHY_MODES[mode]
    return "unknown"


def _network(raw: Any) -> Network | None:
    channel = raw.wlanChannel()
    if channel is None:
        return None
    return Network(
        ssid=raw.ssid(),
        bssid=raw.bssid(),
        rssi=raw.rssiValue(),
        noise=raw.noiseMeasurement() or None,  # 0 means not measured
        band=_band(channel),
        channel=channel.channelNumber(),
        width=_WIDTHS.get(channel.channelWidth(), 20),
        security=security_from_flags([m for m in Security if raw.supportsSecurity_(m)]),
        phy=_phy(raw.supportsPHYMode_),
        beacon_interval=raw.beaconInterval() or None,
    )


class CoreWLANScanner(Scanner):
    def __init__(self, interface: str | None = None) -> None:
        try:
            import CoreWLAN
            from objc import autorelease_pool
        except ImportError as e:
            raise ScanError("CoreWLAN isn't available. It comes with pyobjc-framework-CoreWLAN.") from e
        # Objective-C objects created off the main thread need a pool to be released into, and the
        # desktop app scans on a worker thread. Every call into CoreWLAN runs inside one.
        self._pool: Callable[[], AbstractContextManager[object]] = autorelease_pool
        with self._pool():
            client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
            self._iface = client.interfaceWithName_(interface) if interface else client.interface()
            if self._iface is None:
                raise ScanError(f"No Wi-Fi interface named {interface!r}" if interface else "No Wi-Fi interface found")
            self.name = str(self._iface.interfaceName())

    def connection(self) -> Connection | None:
        with self._pool():
            return self._connection()

    def _connection(self) -> Connection | None:
        iface = self._iface
        channel = iface.wlanChannel()
        rssi = iface.rssiValue()
        if channel is None or rssi == 0:
            return None
        return Connection(
            ssid=iface.ssid(),
            bssid=iface.bssid(),
            rssi=rssi,
            noise=iface.noiseMeasurement() or None,
            tx_rate=iface.transmitRate(),
            band=_band(channel),
            channel=channel.channelNumber(),
            width=_WIDTHS.get(channel.channelWidth(), 20),
            security=SECURITY_NAMES.get(iface.security(), "Unknown"),
            phy=PHY_MODES.get(iface.activePHYMode(), "unknown"),
        )

    def scan(self) -> ScanResult:
        with self._pool():
            if not self._iface.powerOn():
                raise ScanError(f"Wi-Fi is turned off on {self.name}")
            found, error = self._iface.scanForNetworksWithName_includeHidden_error_(None, True, None)
            if error is not None:
                raise ScanError(f"Scan failed: {error.localizedDescription()}")
            connection = self._connection()
            networks = [n for n in map(_network, found or []) if n is not None]
            return ScanResult(
                interface=self.name,
                networks=mark_current(networks, connection),
                connection=connection,
                country=self._iface.countryCode(),
            )
