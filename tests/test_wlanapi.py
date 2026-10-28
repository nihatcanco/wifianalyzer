import ctypes
import re
import struct
import sys

import pytest

from beacons import HE_CAPABILITIES, HT_CAPABILITIES, ht_operation, ie, rsn
from wifianalyzer.models import Band
from wifianalyzer.scanner import AccessDeniedError, ScanError, wlanapi
from wifianalyzer.scanner.wlanapi import (
    GUID,
    WLAN_BSS_ENTRY,
    WLAN_CONNECTION_ATTRIBUTES,
    WLAN_INTERFACE_INFO,
    WLAN_RADIO_STATE,
    BssEntry,
    Interface,
    WlanApiScanner,
    WlanError,
)

WIFI_GUID = bytes(range(16))
USB_GUID = bytes(range(16, 32))
HOME = "a4:2b:b0:00:00:01"


@pytest.mark.parametrize(
    ("name", "size"),
    [
        ("GUID", 16),
        ("DOT11_SSID", 36),
        ("WLAN_INTERFACE_INFO", 532),
        ("WLAN_RATE_SET", 256),
        ("WLAN_BSS_ENTRY", 360),
        ("WLAN_ASSOCIATION_ATTRIBUTES", 68),
        ("WLAN_SECURITY_ATTRIBUTES", 16),
        ("WLAN_CONNECTION_ATTRIBUTES", 604),
        ("WLAN_RADIO_STATE", 772),
    ],
)
def test_structures_match_the_windows_layout(name, size):
    assert ctypes.sizeof(getattr(wlanapi, name)) == size


def test_bss_entry_field_offsets():
    offsets = {name: getattr(WLAN_BSS_ENTRY, name).offset for name, *_ in WLAN_BSS_ENTRY._fields_}
    assert offsets["dot11Bssid"] == 40
    assert offsets["lRssi"] == 56
    assert offsets["ullTimestamp"] == 72
    assert offsets["ulChCenterFrequency"] == 92
    assert offsets["ulIeOffset"] == 352
    assert wlanapi.WLAN_BSS_LIST.wlanBssEntries.offset == 8


def test_guid_is_formatted_like_windows():
    guid = GUID.from_buffer_copy(bytes.fromhex("78563412 3412 7856 9abcdef012345678".replace(" ", "")))
    assert str(guid) == "{12345678-1234-5678-9ABC-DEF012345678}"


# --- Reading buffers ------------------------------------------------------------------


def entry(bssid: str, khz: int, rssi: int, *, ssid: bytes = b"", bss_type: int = 1, phy: int = 10) -> WLAN_BSS_ENTRY:
    e = WLAN_BSS_ENTRY()
    e.dot11Ssid.uSSIDLength = len(ssid)
    e.dot11Ssid.ucSSID[: len(ssid)] = list(ssid)
    e.dot11Bssid[:] = list(bytes.fromhex(bssid.replace(":", "")))
    e.dot11BssType, e.dot11BssPhyType, e.lRssi = bss_type, phy, rssi
    e.usBeaconPeriod, e.usCapabilityInformation, e.ulChCenterFrequency = 100, 0x0011, khz
    return e


def bss_list(*items: tuple[WLAN_BSS_ENTRY, bytes], claimed: int | None = None) -> ctypes.Array:
    """A WLAN_BSS_LIST as the driver lays it out: the entries, then every entry's elements."""
    size = ctypes.sizeof(WLAN_BSS_ENTRY)
    first_ie = 8 + size * len(items)
    total = first_ie + sum(len(ies) for _, ies in items)
    buffer = ctypes.create_string_buffer(total)
    struct.pack_into("=II", buffer, 0, total, len(items) if claimed is None else claimed)
    at_ie = first_ie
    for i, (e, ies) in enumerate(items):
        at = 8 + i * size
        e.ulIeOffset, e.ulIeSize = at_ie - at, len(ies)
        ctypes.memmove(ctypes.addressof(buffer) + at, ctypes.addressof(e), size)
        ctypes.memmove(ctypes.addressof(buffer) + at_ie, ies, len(ies))
        at_ie += len(ies)
    return buffer


HOME_IES = ie(0, b"Home") + HT_CAPABILITIES + ht_operation(36, 0b101) + rsn(2, 8) + HE_CAPABILITIES + ie(7, b"GB ")


def test_read_bss_list():
    buffer = bss_list(
        (entry(HOME, 5_180_000, -48, ssid=b"Home"), HOME_IES),
        (entry("a4:2b:b0:00:00:02", 2_437_000, -70, ssid=b"Cafe", phy=7), b""),
        (entry("a4:2b:b0:00:00:03", 2_412_000, -60, bss_type=2), b""),  # ad hoc: skipped
    )
    home, cafe = wlanapi.read_bss_list(ctypes.addressof(buffer))
    assert home == BssEntry(b"Home", HOME, 10, -48, 100, 0x0011, 5180, HOME_IES)
    assert (cafe.bssid, cafe.frequency, cafe.ies) == ("a4:2b:b0:00:00:02", 2437, b"")


def test_read_bss_list_never_reads_past_the_buffer():
    buffer = bss_list((entry(HOME, 5_180_000, -48), b"\x00\x04Home"), claimed=5)
    e = WLAN_BSS_ENTRY.from_buffer(buffer, 8)
    e.ulIeSize = 4096  # a driver bug: elements that run off the end
    [only] = wlanapi.read_bss_list(ctypes.addressof(buffer))
    assert only.ies == b""


def test_read_interfaces():
    size = ctypes.sizeof(WLAN_INTERFACE_INFO)
    buffer = ctypes.create_string_buffer(8 + 2 * size)
    struct.pack_into("=II", buffer, 0, 2, 0)
    for i, (guid, name, state) in enumerate([(WIFI_GUID, "Intel(R) Wi-Fi 6E AX211", 1), (USB_GUID, "USB adapter", 4)]):
        info = WLAN_INTERFACE_INFO.from_buffer(buffer, 8 + i * size)
        ctypes.memmove(ctypes.addressof(info.InterfaceGuid), guid, 16)
        encoded = name.encode("utf-16-le")
        ctypes.memmove(ctypes.addressof(info.strInterfaceDescription), encoded, len(encoded))
        info.isState = state
    assert wlanapi.read_interfaces(ctypes.addressof(buffer)) == [
        Interface(WIFI_GUID, "Intel(R) Wi-Fi 6E AX211", connected=True),
        Interface(USB_GUID, "USB adapter", connected=False),
    ]


def test_network_reads_elements_and_falls_back_to_the_phy_type():
    home = wlanapi.network(BssEntry(b"Home", HOME, 10, -48, 100, 0x0011, 5180, HOME_IES))
    assert (home.ssid, home.band, home.channel, home.width, home.security, home.phy) == (
        "Home",
        Band.GHZ_5,
        36,
        40,
        "WPA2/WPA3",
        "802.11ax",
    )
    bare = wlanapi.network(BssEntry(b"", HOME, 8, -60, 100, 0x0001, 5745, b""))
    assert (bare.ssid, bare.channel, bare.phy, bare.security, bare.noise) == (None, 149, "802.11ac", "Open", None)
    assert wlanapi.network(BssEntry(b"x", HOME, 8, -60, 100, 0, 60480, b"")) is None  # 60 GHz


# --- The scanner, on a fake API --------------------------------------------------------


def connection_attributes(*, state: int = 1, phy: int = 10, quality: int = 80) -> WLAN_CONNECTION_ATTRIBUTES:
    attrs = WLAN_CONNECTION_ATTRIBUTES()
    attrs.isState = state
    link = attrs.wlanAssociationAttributes
    link.dot11Ssid.uSSIDLength = 4
    link.dot11Ssid.ucSSID[:4] = list(b"Home")
    link.dot11Bssid[:] = list(bytes.fromhex(HOME.replace(":", "")))
    link.dot11PhyType, link.wlanSignalQuality, link.ulTxRate = phy, quality, 1_200_900
    attrs.wlanSecurityAttributes.bSecurityEnabled = 1
    attrs.wlanSecurityAttributes.dot11AuthAlgorithm = 7
    return attrs


class FakeApi:
    def __init__(self) -> None:
        self.interfaces_list = [Interface(USB_GUID, "USB adapter", False), Interface(WIFI_GUID, "Intel Wi-Fi", True)]
        self.entries = [
            BssEntry(b"Home", HOME, 10, -48, 100, 0x0011, 5180, HOME_IES),
            BssEntry(b"Cafe", "a4:2b:b0:00:00:02", 7, -70, 100, 0x0001, 2437, b""),
        ]
        self.errors: dict[str, int] = {}
        self.connection = connection_attributes()
        self.radio_on = True
        self.rssi = -47
        self.channel = 36
        self.handler = None
        self.scanned = []
        self.closed = False

    def _fail(self, function):
        if function in self.errors:
            raise WlanError(self.errors[function], function)

    def close(self):
        self.closed = True

    def interfaces(self):
        self._fail("WlanEnumInterfaces")
        return self.interfaces_list

    def on_scan_finished(self, guid, handler):
        self._fail("WlanRegisterNotification")
        self.handler = handler

    def scan(self, guid):
        self._fail("WlanScan")
        self.scanned.append(guid)
        if self.handler:
            self.handler()

    def bss_list(self, guid, ssid=None, *, secured=False):
        self._fail("WlanGetNetworkBssList")
        return [e for e in self.entries if ssid is None or e.ssid == ssid]

    def query(self, guid, opcode, kind):
        self._fail(f"query {opcode}")
        if opcode == 7:
            if self.connection is None:
                raise WlanError(wlanapi.ERROR_INVALID_STATE, "WlanQueryInterface")
            return self.connection
        if opcode == 0x10000102:
            return wlanapi.LONG(self.rssi)
        if opcode == 8:
            return wlanapi.ULONG(self.channel)
        if opcode == 4:
            state = WLAN_RADIO_STATE()
            state.dwNumberOfPhys = 1
            state.PhyRadioState[0].dot11SoftwareRadioState = 1 if self.radio_on else 2
            state.PhyRadioState[0].dot11HardwareRadioState = 1
            return state
        raise AssertionError(opcode)


def make_scanner(api, interface=None, aliases=None):
    aliases = {WIFI_GUID: "Wi-Fi", USB_GUID: "Wi-Fi 2"} if aliases is None else aliases
    return WlanApiScanner(interface, api=lambda: api, alias=aliases.get)


def test_scan_reads_networks_connection_and_country():
    api = FakeApi()
    scanner = make_scanner(api)
    assert scanner.name == "Wi-Fi"  # the connected interface, by the name Windows shows
    result = scanner.scan()
    assert api.scanned == [WIFI_GUID]
    assert result.interface == "Wi-Fi"
    assert result.country == "GB"
    home, cafe = result.networks
    assert home.is_current
    assert (cafe.ssid, cafe.channel, cafe.phy, cafe.security) == ("Cafe", 6, "802.11n", "Open")
    conn = result.connection
    assert (conn.ssid, conn.bssid, conn.rssi, conn.noise, conn.tx_rate) == ("Home", HOME, -47, None, 1200.9)
    assert (conn.band, conn.channel, conn.width, conn.security, conn.phy) == (
        Band.GHZ_5,
        36,
        40,
        "WPA2/WPA3",
        "802.11ax",
    )


def test_connection_falls_back_to_signal_quality_and_the_channel_number():
    api = FakeApi()
    api.entries = []
    api.errors["query 268435714"] = 50  # no RSSI opcode
    conn = make_scanner(api).connection()
    assert conn.rssi == -60  # 80 % quality
    assert (conn.band, conn.channel, conn.width, conn.security) == (Band.GHZ_5, 36, 20, "WPA2")


def test_not_connected():
    api = FakeApi()
    api.connection = None
    assert make_scanner(api).connection() is None
    api.connection = connection_attributes(state=4)
    assert make_scanner(api).connection() is None


@pytest.mark.parametrize("function", ["WlanGetNetworkBssList", "query 7", "WlanScan"])
def test_location_permission_is_explained(function):
    api = FakeApi()
    api.errors[function] = wlanapi.ERROR_ACCESS_DENIED
    with pytest.raises(AccessDeniedError, match="Let desktop apps access your location"):
        make_scanner(api).scan()


def test_radio_off():
    api = FakeApi()
    api.radio_on = False
    api.errors["WlanScan"] = 0x80342002
    with pytest.raises(ScanError, match="Wi-Fi is turned off on Wi-Fi"):
        make_scanner(api).scan()


def test_wlan_service_not_running_closes_the_handle():
    api = FakeApi()
    api.errors["WlanEnumInterfaces"] = wlanapi.ERROR_SERVICE_NOT_ACTIVE
    with pytest.raises(ScanError, match="WLAN AutoConfig service isn't running"):
        make_scanner(api)
    assert api.closed


def test_without_notifications_scans_wait_a_fixed_time(monkeypatch):
    monkeypatch.setattr(wlanapi, "_DRIVER_SCAN_TIME", 0.01)
    api = FakeApi()
    api.errors["WlanRegisterNotification"] = 5
    assert len(make_scanner(api).scan().networks) == 2


@pytest.mark.parametrize(
    "wanted",
    [
        "Wi-Fi 2",
        "wi-fi 2",
        "USB adapter",
        "{13121110-1514-1716-1819-1A1B1C1D1E1F}",
        "13121110-1514-1716-1819-1a1b1c1d1e1f",
    ],
)
def test_choose_an_interface_by_alias_description_or_guid(wanted):
    assert make_scanner(FakeApi(), wanted).name == "Wi-Fi 2"


def test_unknown_interface_lists_the_available_ones():
    api = FakeApi()
    with pytest.raises(ScanError, match=re.escape("No Wi-Fi interface named 'Ethernet'. Available: Wi-Fi 2, Wi-Fi")):
        make_scanner(api, "Ethernet")
    assert api.closed


def test_no_interfaces():
    api = FakeApi()
    api.interfaces_list = []
    with pytest.raises(ScanError, match="No Wi-Fi interface found"):
        make_scanner(api)


def test_descriptions_stand_in_for_missing_aliases():
    assert make_scanner(FakeApi(), aliases={}).name == "Intel Wi-Fi"


def test_cancel_wakes_a_waiting_scan():
    api = FakeApi()
    scanner = make_scanner(api)
    api.handler = None  # the notification never comes
    scanner.cancel()
    scanner._finished.clear = lambda: None  # keep the cancellation from being reset by scan()
    assert len(scanner.scan().networks) == 2


@pytest.mark.skipif(sys.platform != "win32", reason="loads wlanapi.dll")
def test_the_real_api_opens_or_explains_why_not():
    # CI machines have no Wi-Fi adapter; either way, failures must be ScanErrors with a message.
    error = None
    try:
        wlanapi.WlanApiScanner().close()
    except ScanError as e:
        error = e
    assert error is None or str(error)
