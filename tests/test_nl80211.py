import errno
import re
import struct
import subprocess
from dataclasses import dataclass, field

import pytest

from beacons import HE_CAPABILITIES, HT_CAPABILITIES, VHT_CAPABILITIES, ht_operation, ie, rsn, vht_operation
from wifianalyzer.models import Band
from wifianalyzer.scanner import ScanError, nl80211
from wifianalyzer.scanner.netlink import (
    Family,
    Message,
    NetlinkError,
    attr,
    attr_nested,
    attr_str,
    attr_u32,
    parse_attrs,
)
from wifianalyzer.scanner.nl80211 import Nl80211Scanner

FAMILY = 0x1C
HOME = "a4:2b:b0:00:00:01"
NEIGHBOUR = "a4:2b:b0:00:00:02"
HOME_IES = (
    ie(0, b"Home") + HT_CAPABILITIES + ht_operation(36, 0b101) + rsn(2, 8) + VHT_CAPABILITIES + vht_operation(1, 42, 0)
)
HOME_IES += HE_CAPABILITIES


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def message(cmd: int, *attrs: bytes) -> Message:
    return Message(FAMILY, 0, 1, cmd, parse_attrs(b"".join(attrs)))


def bss(bssid: str, mhz: int, mbm: int, ies: bytes, *, associated: bool = False, capability: int = 0x0011) -> Message:
    fields = [
        attr(nl80211.BSS_BSSID, mac(bssid)),
        attr_u32(nl80211.BSS_FREQUENCY, mhz),
        attr(nl80211.BSS_SIGNAL_MBM, struct.pack("=i", mbm)),
        attr(nl80211.BSS_CAPABILITY, struct.pack("=H", capability)),
        attr(nl80211.BSS_BEACON_INTERVAL, struct.pack("=H", 100)),
        attr(nl80211.BSS_INFORMATION_ELEMENTS, ies),
    ]
    if associated:
        fields.append(attr_u32(nl80211.BSS_STATUS, nl80211.BSS_STATUS_ASSOCIATED))
    return message(nl80211.CMD_NEW_SCAN_RESULTS, attr_nested(nl80211.ATTR_BSS, *fields))


def interface(index: int, name: str, *, mhz: int | None = None, width: int | None = None, ssid: bytes = b"") -> Message:
    fields = [
        attr_u32(nl80211.ATTR_IFINDEX, index),
        attr_str(nl80211.ATTR_IFNAME, name),
        attr_u32(nl80211.ATTR_IFTYPE, nl80211.IFTYPE_STATION),
    ]
    if mhz:
        fields += [attr_u32(nl80211.ATTR_WIPHY_FREQ, mhz), attr(nl80211.ATTR_SSID, ssid)]
    if width is not None:
        fields.append(attr_u32(nl80211.ATTR_CHANNEL_WIDTH, width))
    return message(nl80211.CMD_GET_INTERFACE, *fields)


@dataclass
class Kernel:
    """A scripted stand-in for nl80211."""

    interfaces: list[Message] = field(default_factory=lambda: [interface(3, "wlan0", mhz=5180, width=3, ssid=b"Home")])
    scan: list[Message] = field(
        default_factory=lambda: [
            bss(HOME, 5180, -5400, HOME_IES, associated=True),
            bss(NEIGHBOUR, 2437, -7120, ie(0, b"Cafe") + HT_CAPABILITIES + ht_operation(6, 0), capability=0x0001),
            bss("a4:2b:b0:00:00:03", 4920, -6000, b""),  # 4.9 GHz, which isn't charted
        ]
    )
    trigger_error: int | None = None
    regulatory: str = "DE"
    finished: bool = True
    requests: list[tuple[int, dict[int, bytes]]] = field(default_factory=list)
    subscribed: list[int] = field(default_factory=list)
    closed: int = 0

    def request(self, family, cmd, *attrs, dump=False, version=0):
        assert family == FAMILY
        self.requests.append((cmd, parse_attrs(b"".join(attrs))))
        if cmd == nl80211.CMD_GET_INTERFACE:
            return self.interfaces if dump else self.interfaces[:1]
        if cmd == nl80211.CMD_TRIGGER_SCAN:
            if self.trigger_error is not None:
                raise NetlinkError(self.trigger_error, "refused")
            return []
        if cmd == nl80211.CMD_GET_SCAN:
            return self.scan
        if cmd == nl80211.CMD_GET_STATION:
            rate = attr_nested(
                nl80211.STA_INFO_TX_BITRATE,
                attr_u32(nl80211.RATE_INFO_BITRATE32, 8647),
                attr(nl80211.RATE_INFO_HE_MCS, b"\x0b"),
            )
            info = attr_nested(nl80211.ATTR_STA_INFO, attr(nl80211.STA_INFO_SIGNAL, struct.pack("=b", -52)), rate)
            return [message(nl80211.CMD_GET_STATION, info)]
        if cmd == nl80211.CMD_GET_SURVEY:
            other = attr_nested(nl80211.ATTR_SURVEY_INFO, attr_u32(1, 2412), attr(2, struct.pack("=b", -95)))
            in_use = attr_nested(nl80211.ATTR_SURVEY_INFO, attr_u32(1, 5180), attr(2, struct.pack("=b", -91)), attr(3))
            return [message(nl80211.CMD_GET_SURVEY, other), message(nl80211.CMD_GET_SURVEY, in_use)]
        if cmd == nl80211.CMD_GET_REG:
            return [message(nl80211.CMD_GET_REG, attr_str(nl80211.ATTR_REG_ALPHA2, self.regulatory))]
        raise AssertionError(f"unexpected command {cmd}")

    def commands(self):
        return [cmd for cmd, _ in self.requests]


class FakeNetlink:
    def __init__(self, kernel: Kernel) -> None:
        self.kernel = kernel

    def resolve(self, name):
        assert name == "nl80211"
        return Family(FAMILY, {"scan": 4, "mlme": 5})

    def request(self, *args, **kwargs):
        return self.kernel.request(*args, **kwargs)

    def subscribe(self, group):
        self.kernel.subscribed.append(group)

    def wait_for(self, match, timeout, cancelled):
        event = message(nl80211.CMD_NEW_SCAN_RESULTS, attr_u32(nl80211.ATTR_IFINDEX, 3))
        return self.kernel.finished and match(event)

    def close(self):
        self.kernel.closed += 1


@pytest.fixture
def kernel():
    return Kernel()


@pytest.fixture
def sysfs(tmp_path):
    device = tmp_path / "wlan0"
    device.mkdir()
    (device / "flags").write_text("0x1003\n")
    return tmp_path


def scanner(kernel, sysfs, interface=None):
    return Nl80211Scanner(interface, connect=lambda: FakeNetlink(kernel), sysfs=sysfs)


def test_scan_reads_networks_and_connection(kernel, sysfs):
    result = scanner(kernel, sysfs).scan()
    assert result.interface == "wlan0"
    assert result.country == "DE"
    home, cafe = result.networks  # 4.9 GHz is left out
    assert (home.ssid, home.bssid, home.rssi, home.band, home.channel, home.width) == (
        "Home",
        HOME,
        -54,
        Band.GHZ_5,
        36,
        80,
    )
    assert (home.security, home.phy, home.beacon_interval, home.is_current) == ("WPA2/WPA3", "802.11ax", 100, True)
    assert (cafe.ssid, cafe.rssi, cafe.band, cafe.channel, cafe.width, cafe.security) == (
        "Cafe",
        -71,
        Band.GHZ_2_4,
        6,
        20,
        "Open",
    )
    assert cafe.phy == "802.11n"
    conn = result.connection
    assert (conn.ssid, conn.bssid, conn.rssi, conn.noise, conn.snr) == ("Home", HOME, -52, -91, 39)
    assert (conn.band, conn.channel, conn.width, conn.tx_rate, conn.phy) == (Band.GHZ_5, 36, 80, 864.7, "802.11ax")


def test_scan_triggers_an_active_scan_and_waits_on_a_separate_socket(kernel, sysfs):
    scanner(kernel, sysfs).scan()
    _, attrs = next(r for r in kernel.requests if r[0] == nl80211.CMD_TRIGGER_SCAN)
    assert attrs.u32(nl80211.ATTR_IFINDEX) == 3
    assert attrs.nested(nl80211.ATTR_SCAN_SSIDS).get(1) == b""  # the wildcard name
    assert kernel.subscribed == [4]
    assert kernel.closed == 1  # the listener; the main socket stays open


def test_without_permission_it_asks_networkmanager(kernel, sysfs, monkeypatch):
    kernel.trigger_error = errno.EPERM
    ran = []
    monkeypatch.setattr(nl80211.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "nmcli" else None)
    monkeypatch.setattr(
        nl80211.subprocess, "run", lambda command, **_: ran.append(command) or subprocess.CompletedProcess(command, 0)
    )
    result = scanner(kernel, sysfs).scan()
    assert ran == [["/usr/bin/nmcli", "device", "wifi", "rescan", "ifname", "wlan0"]]
    assert len(result.networks) == 2


def test_without_permission_or_helpers_it_uses_the_latest_results(kernel, sysfs, monkeypatch):
    kernel.trigger_error = errno.EPERM
    kernel.finished = False
    monkeypatch.setattr(nl80211.shutil, "which", lambda name: None)
    assert len(scanner(kernel, sysfs).scan().networks) == 2


def test_helpers_that_refuse_fall_through_to_the_next(kernel, sysfs, monkeypatch):
    kernel.trigger_error = errno.EPERM
    ran = []

    def run(command, **_):
        ran.append(command[0])
        return subprocess.CompletedProcess(command, 1 if "nmcli" in command[0] else 0, stderr="not managed")

    monkeypatch.setattr(nl80211.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(nl80211.subprocess, "run", run)
    scanner(kernel, sysfs).scan()
    assert ran == ["/usr/bin/nmcli", "/usr/bin/iwctl"]


@pytest.mark.parametrize(
    ("code", "message"),
    [(132, "Wi-Fi is turned off on wlan0"), (errno.ENETDOWN, "wlan0 is down. Turn Wi-Fi on and try again.")],
)
def test_trigger_errors_explain_themselves(kernel, sysfs, code, message):
    kernel.trigger_error = code
    with pytest.raises(ScanError, match=message):
        scanner(kernel, sysfs).scan()


def test_a_blocked_radio_is_reported_before_scanning(kernel, sysfs):
    switch = sysfs / "wlan0" / "phy80211" / "rfkill1"
    switch.mkdir(parents=True)
    (switch / "soft").write_text("1\n")
    (switch / "hard").write_text("0\n")
    with pytest.raises(ScanError, match="Wi-Fi is turned off on wlan0"):
        scanner(kernel, sysfs).scan()
    assert nl80211.CMD_TRIGGER_SCAN not in kernel.commands()


def test_a_down_interface_is_reported(kernel, sysfs):
    (sysfs / "wlan0" / "flags").write_text("0x1002\n")
    with pytest.raises(ScanError, match="wlan0 is down"):
        scanner(kernel, sysfs).scan()


def test_disconnected(kernel, sysfs):
    kernel.interfaces = [interface(3, "wlan0")]
    kernel.scan = [bss(NEIGHBOUR, 2437, -7000, ie(0, b"Cafe"))]
    result = scanner(kernel, sysfs).scan()
    assert result.connection is None
    assert not any(n.is_current for n in result.networks)


def test_connection_polls_without_scanning(kernel, sysfs):
    conn = scanner(kernel, sysfs).connection()
    assert conn.rssi == -52
    assert nl80211.CMD_TRIGGER_SCAN not in kernel.commands()


def test_world_regulatory_domain_falls_back_to_access_points(kernel, sysfs):
    kernel.regulatory = "00"
    kernel.scan = [bss(HOME, 5180, -5400, HOME_IES + ie(7, b"FR\x20"), associated=True)]
    assert scanner(kernel, sysfs).scan().country == "FR"


def test_interface_choice(kernel, sysfs):
    kernel.interfaces = [interface(2, "wlp1s0"), interface(3, "wlan0", mhz=5180)]
    assert scanner(kernel, sysfs).name == "wlan0"  # the connected one
    assert scanner(kernel, sysfs, "wlp1s0").name == "wlp1s0"
    with pytest.raises(ScanError, match=re.escape("No Wi-Fi interface named 'eth0'. Available: wlp1s0, wlan0")):
        scanner(kernel, sysfs, "eth0")
    assert kernel.closed == 1


def test_no_wifi_hardware(sysfs):
    kernel = Kernel(interfaces=[])
    with pytest.raises(ScanError, match="No Wi-Fi interface found"):
        scanner(kernel, sysfs)


def test_no_wifi_driver(sysfs):
    class NoFamily(FakeNetlink):
        def resolve(self, name):
            raise NetlinkError(errno.ENOENT, "missing")

    with pytest.raises(ScanError, match="no Wi-Fi driver is loaded"):
        Nl80211Scanner(connect=lambda: NoFamily(Kernel()), sysfs=sysfs)


def test_rate_standard():
    assert nl80211.rate_standard({nl80211.RATE_INFO_EHT_MCS: b"", nl80211.RATE_INFO_HE_MCS: b""}) == "802.11be"
    assert nl80211.rate_standard({nl80211.RATE_INFO_VHT_MCS: b""}) == "802.11ac"
    assert nl80211.rate_standard({nl80211.RATE_INFO_MCS: b""}) == "802.11n"
    assert nl80211.rate_standard({}) is None


def test_bss_without_dbm_signal_uses_the_unspecified_scale():
    entry = message(
        nl80211.CMD_NEW_SCAN_RESULTS,
        attr_nested(
            nl80211.ATTR_BSS,
            attr(nl80211.BSS_BSSID, mac(HOME)),
            attr_u32(nl80211.BSS_FREQUENCY, 2412),
            attr(nl80211.BSS_SIGNAL_UNSPEC, b"\x50"),
        ),
    )
    assert nl80211.read_bss(entry).rssi == -60
