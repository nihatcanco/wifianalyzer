"""Scans as files: JSON for Save Scan and Open Scan, CSV for spreadsheets."""

from __future__ import annotations

import csv
import io
import json
import math
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime
from typing import Any, TypeVar

from .analysis import BandReport, signal_quality
from .channels import block_label, is_dfs
from .display import index_networks, phy_label, printable
from .models import Band, Connection, Network, ScanResult

T = TypeVar("T")

# Values the app's channel math and charts can work with. Anything else didn't come from a scan.
_WIDTHS = frozenset({20, 40, 80, 160, 320})
_CHANNELS = range(1, 234)
_DBM = range(-150, 1)


class ScanFileError(ValueError):
    """The file isn't a scan saved by this app, or has been changed so that it no longer reads as one."""


def _encode(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def to_json(result: ScanResult, reports: Sequence[BandReport]) -> str:
    """The scan and its channel recommendations. Non-ASCII characters in names are escaped."""
    data = asdict(result)
    data["recommendations"] = [asdict(r) for r in reports]
    return json.dumps(data, default=_encode, indent=2)


def from_json(text: str | bytes) -> ScanResult:
    """A scan written by ``to_json``. The recommendations in it are ignored: they follow from the scan.

    Saved files can be edited or come from someone else, so every value is checked before the app
    draws or scores it.
    """
    try:
        data = json.loads(text)
    except ValueError as e:  # including bytes that aren't text
        raise ScanFileError("it isn't valid JSON") from e
    scan = _object(data, "the file")
    networks = _get(scan, "networks", list)
    connection = _optional(scan, "connection", dict)
    timestamp = _get(scan, "timestamp", str)
    try:
        when = datetime.fromisoformat(timestamp)
    except ValueError as e:
        raise ScanFileError('"timestamp" isn\'t a date and time') from e
    return ScanResult(
        interface=_get(scan, "interface", str),
        networks=[_network(_object(n, f"network {i}")) for i, n in enumerate(networks, start=1)],
        connection=None if connection is None else _connection(connection),
        country=_optional(scan, "country", str),
        timestamp=when if when.tzinfo else when.astimezone(),
    )


def _network(data: dict[str, Any]) -> Network:
    band, channel, width = _channel(data)
    return Network(
        ssid=_optional(data, "ssid", str),
        bssid=_optional(data, "bssid", str),
        rssi=_dbm(data, "rssi"),
        noise=_optional_dbm(data, "noise"),
        band=band,
        channel=channel,
        width=width,
        security=_get(data, "security", str),
        phy=_get(data, "phy", str),
        beacon_interval=_optional(data, "beacon_interval", int),
        is_current=bool(_optional(data, "is_current", bool)),
    )


def _connection(data: dict[str, Any]) -> Connection:
    band, channel, width = _channel(data)
    return Connection(
        ssid=_optional(data, "ssid", str),
        bssid=_optional(data, "bssid", str),
        rssi=_dbm(data, "rssi"),
        noise=_optional_dbm(data, "noise"),
        tx_rate=_rate(data, "tx_rate"),
        band=band,
        channel=channel,
        width=width,
        security=_get(data, "security", str),
        phy=_get(data, "phy", str),
    )


def _object(value: object, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ScanFileError(f"{what} isn't a JSON object")
    return value


def _channel(data: dict[str, Any]) -> tuple[Band, int, int]:
    try:
        band = Band(_get(data, "band", str))
    except ValueError as e:
        raise ScanFileError('"band" isn\'t 2.4, 5 or 6') from e
    channel, width = _get(data, "channel", int), _get(data, "width", int)
    if channel not in _CHANNELS:
        raise ScanFileError('"channel" is out of range')
    if width not in _WIDTHS:
        raise ScanFileError('"width" isn\'t a channel width')
    return band, channel, width


def _dbm(data: dict[str, Any], key: str) -> int:
    value = _get(data, key, int)
    if value not in _DBM:
        raise ScanFileError(f'"{key}" is out of range')
    return value


def _optional_dbm(data: dict[str, Any], key: str) -> int | None:
    return None if data.get(key) is None else _dbm(data, key)


def _rate(data: dict[str, Any], key: str) -> float:
    value = data.get(key)
    try:
        rate = float(value) if isinstance(value, int | float) and not isinstance(value, bool) else math.nan
    except OverflowError:  # a whole number too large for a float
        rate = math.nan
    # Python reads JSON's NaN and Infinity too, and neither is a rate.
    if not math.isfinite(rate):
        raise ScanFileError(f'"{key}" is missing or isn\'t a number')
    return rate


def _get(data: dict[str, Any], key: str, kind: type[T]) -> T:
    if key not in data:
        raise ScanFileError(f'"{key}" is missing')
    value = data[key]
    # JSON's true and false arrive as bool, which Python counts as int.
    if not isinstance(value, kind) or (isinstance(value, bool) and kind is not bool):
        raise ScanFileError(f'"{key}" has the wrong type')
    return value


def _optional(data: dict[str, Any], key: str, kind: type[T]) -> T | None:
    return None if data.get(key) is None else _get(data, key, kind)


CSV_COLUMNS = (
    "Time", "Band", "#", "Network", "BSSID", "Signal (dBm)", "Quality (%)", "Noise (dBm)", "SNR (dB)",
    "Channel", "Channels", "Width (MHz)", "DFS", "Security", "Standard", "Connected",
)  # fmt: skip

# Spreadsheets run a cell that starts with one of these as a formula, and network names come from strangers.
_FORMULA_STARTS = ("=", "+", "-", "@", "\t", "\r")


def _cell(text: str) -> str:
    return "'" + text if text.startswith(_FORMULA_STARTS) else text


def to_csv(result: ScanResult) -> str:
    """Every network in the scan, one row each, grouped by band and numbered as in the app.

    Names are escaped as the app shows them, and text that a spreadsheet would run as a formula is
    prefixed with an apostrophe. Lines end in CRLF, as RFC 4180 asks.
    """
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    time = result.timestamp.isoformat(timespec="seconds")
    for band in Band:
        for index, n in index_networks(n for n in result.networks if n.band is band):
            writer.writerow([
                time,
                band.label,
                index,
                _cell(printable(n.ssid)) if n.ssid else "",
                _cell(n.bssid or ""),
                n.rssi,
                signal_quality(n.rssi),
                "" if n.noise is None else n.noise,
                "" if n.snr is None else n.snr,
                n.channel,
                block_label(n.band, n.channel, n.width),
                n.width,
                "yes" if is_dfs(n.band, n.channel, n.width) else "no",
                _cell(n.security),
                _cell(phy_label(n.phy, n.band)),
                "yes" if n.is_current else "no",
            ])  # fmt: skip
    return out.getvalue()
