"""Scanning on Linux through nl80211, the kernel's interface to Wi-Fi drivers.

Any user may read scan results and link statistics. Starting a scan needs the CAP_NET_ADMIN
capability, so without it the scanner asks NetworkManager or iwd to scan, as their own
desktop tools do. If neither is available it reports the networks from the system's latest
scan, which these services repeat on their own every few minutes.
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..channels import from_frequency
from ..models import Connection, Network, ScanResult
from . import elements
from .base import ScanError, Scanner, common_country, format_mac, mark_current
from .netlink import GenericNetlink, Message, NetlinkError, attr, attr_nested, attr_u32

log = logging.getLogger(__name__)

# From include/uapi/linux/nl80211.h.
CMD_GET_INTERFACE = 5
CMD_GET_STATION = 17
CMD_GET_REG = 31
CMD_GET_SCAN = 32
CMD_TRIGGER_SCAN = 33
CMD_NEW_SCAN_RESULTS = 34
CMD_SCAN_ABORTED = 35
CMD_GET_SURVEY = 50

ATTR_IFINDEX = 3
ATTR_IFNAME = 4
ATTR_IFTYPE = 5
ATTR_MAC = 6
ATTR_STA_INFO = 21
ATTR_REG_ALPHA2 = 33
ATTR_WIPHY_FREQ = 38
ATTR_SCAN_SSIDS = 45
ATTR_BSS = 47
ATTR_SSID = 52
ATTR_SURVEY_INFO = 84
ATTR_CHANNEL_WIDTH = 159

IFTYPE_STATION = 2

BSS_BSSID = 1
BSS_FREQUENCY = 2
BSS_BEACON_INTERVAL = 4
BSS_CAPABILITY = 5
BSS_INFORMATION_ELEMENTS = 6
BSS_SIGNAL_MBM = 7
BSS_SIGNAL_UNSPEC = 8
BSS_STATUS = 9
BSS_BEACON_IES = 11
BSS_STATUS_ASSOCIATED = 1

STA_INFO_SIGNAL = 7
STA_INFO_TX_BITRATE = 8
RATE_INFO_BITRATE = 1  # 100 kb/s units
RATE_INFO_MCS = 2
RATE_INFO_BITRATE32 = 5
RATE_INFO_VHT_MCS = 6
RATE_INFO_HE_MCS = 13
RATE_INFO_EHT_MCS = 19

SURVEY_INFO_FREQUENCY = 1
SURVEY_INFO_NOISE = 2
SURVEY_INFO_IN_USE = 3

# enum nl80211_chan_width in MHz. 80+80 counts as its primary 80 MHz, as everywhere else.
_CHANNEL_WIDTHS = {0: 20, 1: 20, 2: 40, 3: 80, 4: 80, 5: 160, 13: 320}
_CAPABILITY_PRIVACY = 0x0010
_IFF_UP = 0x1
_ERFKILL = 132  # Linux's errno; Python only names it on Linux

SCAN_TIMEOUT = 10.0
_RESCAN_COMMANDS = (
    ("nmcli", "device", "wifi", "rescan", "ifname", "{name}"),
    ("iwctl", "station", "{name}", "scan"),
)


@dataclass(frozen=True)
class Interface:
    index: int
    name: str
    frequency: int | None
    """MHz of the primary channel while connected."""
    width: int | None
    ssid: bytes | None


@dataclass(frozen=True)
class Bss:
    bssid: str
    frequency: int
    rssi: int | None
    capability: int
    beacon_interval: int | None
    ies: bytes
    associated: bool

    @property
    def privacy(self) -> bool:
        return bool(self.capability & _CAPABILITY_PRIVACY)


def read_interface(message: Message) -> Interface | None:
    a = message.attrs
    index, name = a.u32(ATTR_IFINDEX), a.string(ATTR_IFNAME)
    if a.u32(ATTR_IFTYPE) != IFTYPE_STATION or index is None or not name:
        return None
    width = a.u32(ATTR_CHANNEL_WIDTH)
    return Interface(
        index=index,
        name=name,
        frequency=a.u32(ATTR_WIPHY_FREQ),
        width=None if width is None else _CHANNEL_WIDTHS.get(width),
        ssid=a.get(ATTR_SSID),
    )


def read_bss(message: Message) -> Bss | None:
    bss = message.attrs.nested(ATTR_BSS)
    bssid, frequency = bss.get(BSS_BSSID), bss.u32(BSS_FREQUENCY)
    if bssid is None or frequency is None:
        return None
    mbm, unspecified = bss.s32(BSS_SIGNAL_MBM), bss.u8(BSS_SIGNAL_UNSPEC)
    if mbm is not None:
        rssi: int | None = round(mbm / 100)
    elif unspecified is not None:
        rssi = -100 + unspecified // 2  # 0 to 100, mapped onto the same range Windows uses
    else:
        rssi = None
    # Probe responses carry the most complete elements; fall back to the beacon's.
    ies = bss.get(BSS_INFORMATION_ELEMENTS) or bss.get(BSS_BEACON_IES) or b""
    return Bss(
        bssid=format_mac(bssid),
        frequency=frequency,
        rssi=rssi,
        capability=bss.u16(BSS_CAPABILITY) or 0,
        beacon_interval=bss.u16(BSS_BEACON_INTERVAL) or None,
        ies=ies,
        associated=bss.u32(BSS_STATUS) == BSS_STATUS_ASSOCIATED,
    )


def network(bss: Bss) -> Network | None:
    located = from_frequency(bss.frequency)
    if located is None or bss.rssi is None:
        return None
    band, channel = located
    advertised = elements.parse(bss.ies, band, privacy=bss.privacy)
    return Network(
        ssid=advertised.ssid,
        bssid=bss.bssid,
        rssi=bss.rssi,
        noise=None,  # only measured for the channel in use
        band=band,
        channel=channel,
        width=advertised.width,
        security=advertised.security,
        phy=advertised.phy,
        beacon_interval=bss.beacon_interval,
    )


def rate_standard(rate: dict[int, bytes]) -> str | None:
    """The standard of a transmit rate, from which kind of MCS index it carries."""
    for kind, name in (
        (RATE_INFO_EHT_MCS, "802.11be"),
        (RATE_INFO_HE_MCS, "802.11ax"),
        (RATE_INFO_VHT_MCS, "802.11ac"),
        (RATE_INFO_MCS, "802.11n"),
    ):
        if kind in rate:
            return name
    return None


def _scan_finished(index: int) -> Callable[[Message], bool]:
    def match(message: Message) -> bool:
        return message.cmd in (CMD_NEW_SCAN_RESULTS, CMD_SCAN_ABORTED) and message.attrs.u32(ATTR_IFINDEX) == index

    return match


class Nl80211Scanner(Scanner):
    def __init__(
        self,
        interface: str | None = None,
        *,
        connect: Callable[[], GenericNetlink] = GenericNetlink,
        sysfs: Path = Path("/sys/class/net"),
    ) -> None:
        self._connect = connect
        self._sysfs = sysfs
        self._cancelled = threading.Event()
        try:
            self._nl = connect()
        except OSError as e:
            raise ScanError(f"Couldn't open a netlink socket to the kernel: {e.strerror}") from None
        try:
            family = self._nl.resolve("nl80211")
            self._family = family.id
            self._scan_group = family.groups.get("scan")
            chosen = self._choose(interface)
        except NetlinkError as e:
            self._nl.close()
            if e.errno == errno.ENOENT:
                raise ScanError("No Wi-Fi interface found: no Wi-Fi driver is loaded") from None
            raise ScanError(f"Couldn't list Wi-Fi interfaces: {e.strerror}") from None
        except ScanError:
            self._nl.close()
            raise
        self._index = chosen.index
        self.name = chosen.name

    def _choose(self, wanted: str | None) -> Interface:
        found = [
            i
            for i in map(read_interface, self._nl.request(self._family, CMD_GET_INTERFACE, dump=True))
            if i is not None
        ]
        if not found:
            raise ScanError("No Wi-Fi interface found")
        if wanted is None:
            return next((i for i in found if i.frequency is not None), found[0])
        match = next((i for i in found if i.name == wanted), None)
        if match is None:
            raise ScanError(f"No Wi-Fi interface named {wanted!r}. Available: {', '.join(i.name for i in found)}")
        return match

    def close(self) -> None:
        self._nl.close()

    def cancel(self) -> None:
        self._cancelled.set()

    # --- Scanning -------------------------------------------------------------------

    def scan(self) -> ScanResult:
        self._check_radio()
        try:
            self._scan_and_wait()
            entries = self._bss_entries()
            connection = self._connection(entries)
        except NetlinkError as e:
            raise ScanError(f"Scan failed: {e.strerror}") from None
        networks = [n for n in map(network, entries) if n is not None]
        return ScanResult(
            interface=self.name,
            networks=mark_current(networks, connection),
            connection=connection,
            country=self._country(entries),
        )

    def _check_radio(self) -> None:
        """Explain why a scan can't run, as far as sysfs tells: the radio is off, or the interface down."""
        device = self._sysfs / self.name
        for switch in device.glob("phy80211/rfkill*"):
            if any(_read(switch / state) == "1" for state in ("soft", "hard")):
                raise ScanError(f"Wi-Fi is turned off on {self.name}")
        flags = _read(device / "flags")
        if flags is not None and not int(flags, 16) & _IFF_UP:
            raise ScanError(f"{self.name} is down. Turn Wi-Fi on, or bring the interface up, and try again.")

    def _scan_and_wait(self) -> None:
        # Listen before asking, so the notification that the scan finished can't be missed.
        listener = self._listener()
        try:
            started = self._start_scan()
            if (
                started
                and listener
                and not listener.wait_for(_scan_finished(self._index), SCAN_TIMEOUT, self._cancelled)
            ):
                log.debug("No scan results within %.0f s; using what the kernel has", SCAN_TIMEOUT)
        finally:
            if listener is not None:
                listener.close()

    def _listener(self) -> GenericNetlink | None:
        if self._scan_group is None:
            return None
        try:
            listener = self._connect()
        except OSError as e:
            log.debug("Can't listen for scan results: %s", e)
            return None
        try:
            listener.subscribe(self._scan_group)
        except OSError as e:
            log.debug("Can't listen for scan results: %s", e)
            listener.close()
            return None
        return listener

    def _start_scan(self) -> bool:
        """Start a scan, or have the system start one. False when the cached results must do."""
        wildcard = attr_nested(ATTR_SCAN_SSIDS, attr(1))  # probe for any network, not just listen
        try:
            self._nl.request(self._family, CMD_TRIGGER_SCAN, attr_u32(ATTR_IFINDEX, self._index), wildcard)
        except NetlinkError as e:
            if e.errno == errno.EBUSY:  # already scanning; its results will do
                return True
            if e.errno == _ERFKILL:
                raise ScanError(f"Wi-Fi is turned off on {self.name}") from None
            if e.errno == errno.ENETDOWN:
                raise ScanError(f"{self.name} is down. Turn Wi-Fi on and try again.") from None
            if e.errno not in (errno.EPERM, errno.EACCES):
                log.warning("Couldn't start a scan: %s", e.strerror)
                return False
            return self._ask_system_to_scan()
        return True

    def _ask_system_to_scan(self) -> bool:
        for template in _RESCAN_COMMANDS:
            program = shutil.which(template[0])
            if program is None:
                continue
            command = [program, *(part.format(name=self.name) for part in template[1:])]
            try:
                done = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=SCAN_TIMEOUT,
                    check=False,
                    env={**os.environ, "LC_ALL": "C"},
                )
            except (OSError, subprocess.TimeoutExpired) as e:
                log.debug("%s failed: %s", template[0], e)
                continue
            if done.returncode == 0:
                log.debug("Asked %s to scan", template[0])
                return True
            # NetworkManager refuses rescans in quick succession; its latest results are fresh then.
            log.debug("%s couldn't scan: %s", template[0], (done.stderr or done.stdout).strip())
        return False

    def _bss_entries(self) -> list[Bss]:
        replies = self._nl.request(self._family, CMD_GET_SCAN, attr_u32(ATTR_IFINDEX, self._index), dump=True)
        return [b for b in map(read_bss, replies) if b is not None]

    def _country(self, entries: list[Bss]) -> str | None:
        """The regulatory domain the kernel applies, or what nearby access points advertise."""
        try:
            replies = self._nl.request(self._family, CMD_GET_REG)
        except NetlinkError:
            replies = []
        code = replies[0].attrs.string(ATTR_REG_ALPHA2) if replies else None
        if code and code.isalpha():  # "00" is the world domain, used until a country is known
            return code
        current = next((b for b in entries if b.associated), None)
        return common_country(
            (elements.country(elements.Elements(b.ies)) for b in entries),
            preferred=elements.country(elements.Elements(current.ies)) if current else None,
        )

    # --- The connection -------------------------------------------------------------

    def connection(self) -> Connection | None:
        try:
            return self._connection(self._bss_entries())
        except NetlinkError as e:
            raise ScanError(f"Couldn't read the connection: {e.strerror}") from None

    def _connection(self, entries: list[Bss]) -> Connection | None:
        current = next((b for b in entries if b.associated), None)
        if current is None:
            return None
        station = self._station(current.bssid)
        interface = self._interface()
        if station is None or interface is None:
            return None
        signal, tx_rate, rate_phy = station
        located = from_frequency(interface.frequency or current.frequency)
        if located is None:
            return None
        band, channel = located
        advertised = elements.parse(current.ies, band, privacy=current.privacy)
        return Connection(
            ssid=elements.decode_ssid(interface.ssid) or advertised.ssid,
            bssid=current.bssid,
            rssi=signal if signal is not None else (current.rssi or -100),
            noise=self._noise(),
            tx_rate=tx_rate,
            band=band,
            channel=channel,
            width=interface.width or advertised.width,
            security=advertised.security,
            phy=rate_phy or advertised.phy,
        )

    def _interface(self) -> Interface | None:
        replies = self._nl.request(self._family, CMD_GET_INTERFACE, attr_u32(ATTR_IFINDEX, self._index))
        return read_interface(replies[0]) if replies else None

    def _station(self, bssid: str) -> tuple[int | None, float, str | None] | None:
        """Signal, transmit rate in Mb/s and that rate's standard, for the access point."""
        mac = bytes.fromhex(bssid.replace(":", ""))
        try:
            replies = self._nl.request(
                self._family, CMD_GET_STATION, attr_u32(ATTR_IFINDEX, self._index), attr(ATTR_MAC, mac)
            )
        except NetlinkError as e:
            if e.errno == errno.ENOENT:  # disassociated in the meantime
                return None
            raise
        if not replies:
            return None
        info = replies[0].attrs.nested(ATTR_STA_INFO)
        rate = info.nested(STA_INFO_TX_BITRATE)
        bitrate = rate.u32(RATE_INFO_BITRATE32) or rate.u16(RATE_INFO_BITRATE) or 0
        return info.s8(STA_INFO_SIGNAL), bitrate / 10, rate_standard(rate)

    def _noise(self) -> int | None:
        """The noise floor of the channel in use, if the driver measures it."""
        try:
            replies = self._nl.request(self._family, CMD_GET_SURVEY, attr_u32(ATTR_IFINDEX, self._index), dump=True)
        except NetlinkError:
            return None
        for reply in replies:
            info = reply.attrs.nested(ATTR_SURVEY_INFO)
            if info.flag(SURVEY_INFO_IN_USE):
                return info.s8(SURVEY_INFO_NOISE) or None
        return None


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None
