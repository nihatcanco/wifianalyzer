"""Builders for networks and connections with sensible defaults."""

from __future__ import annotations

from typing import Any

from wifianalyzer.models import Band, Connection, Network


def make_network(channel: int, rssi: int, band: Band = Band.GHZ_2_4, width: int = 20, **kwargs: Any) -> Network:
    defaults: dict[str, Any] = {"ssid": None, "bssid": None, "noise": None, "security": "WPA2", "phy": "802.11ax"}
    return Network(band=band, channel=channel, rssi=rssi, width=width, **{**defaults, **kwargs})


def make_connection(channel: int, rssi: int, band: Band = Band.GHZ_5, width: int = 80, **kwargs: Any) -> Connection:
    defaults: dict[str, Any] = {
        "ssid": None,
        "bssid": None,
        "noise": -92,
        "tx_rate": 866.0,
        "security": "WPA2",
        "phy": "802.11ax",
    }
    return Connection(band=band, channel=channel, rssi=rssi, width=width, **{**defaults, **kwargs})
